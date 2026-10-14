package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maxpert/marmot/db"
	"github.com/maxpert/marmot/encoding"
	marmotgrpc "github.com/maxpert/marmot/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Cluster-wide data consistency check.
//
// The check is a read-only scatter/gather over the same gRPC channel
// replication uses:
//
//  1. every target node computes a per-table digest locally (row count plus
//     an FNV hash over every row in primary-key order) - GetTableDigests;
//  2. the coordinator compares the digest set: table presence, column
//     signature, row count and hash;
//  3. only for tables whose digest differs does it pull (key, row hash)
//     pages from every node - GetRowHashes - and diffs the key sets, so
//     the report names the exact primary key that disagrees and on which
//     nodes;
//  4. for the first few differing keys it optionally fetches each node's
//     actual values - GetRowData - so the report shows not just where the
//     difference is but what it is.
//
// It never snapshots a common point across nodes: run it against a quiescent
// cluster, or replication in flight can show up as a transient difference.
const (
	consistencyDefaultTimeout  = 30 * time.Second
	consistencyMaxTimeout      = 5 * time.Minute
	consistencyDefaultMismatch = 200 // mismatching rows reported per table
	consistencyMaxMismatch     = 1000
	consistencyValueCap        = 50 // mismatching rows whose values are fetched per table
	consistencyMaxRowPages     = 2000
	consistencyRowPageSize     = 1024
)

// digestInfo is the coordinator's unified view of one node's digest for one
// table, regardless of whether it came from a local scan or a peer RPC.
type digestInfo struct {
	primaryKey   []string
	columns      []db.ConsistencyColumn
	signature    string
	rowCount     int64
	hash         uint64
	withoutRowID bool
}

// nodeRowHash is one row-hash page entry as the coordinator needs it.
type nodeRowHash struct {
	keyBytes []byte
	keyText  string
	hash     uint64
}

// nodeRowData is one requested key's answer from one node.
type nodeRowData struct {
	present bool
	values  map[string]string
}

// rowHashCollection is one node's full (key -> row hash) map for one table,
// plus whether collection stopped at the page cap.
type rowHashCollection struct {
	rows      map[string]nodeRowHash
	truncated bool
	err       error
}

// consistencyFetcher is the per-node data plane the check runs over. The
// local node is read straight from the DatabaseManager; remote nodes go
// through the gRPC client. Tests substitute in-memory fakes.
type consistencyFetcher interface {
	NodeID() uint64
	// FetchDigests returns the node's table digests for database. The
	// boolean reports that the node does not have the database at all.
	FetchDigests(ctx context.Context, database string) (map[string]*digestInfo, bool, error)
	FetchRowHashes(ctx context.Context, database, table string, afterKey []byte) ([]nodeRowHash, []byte, bool, error)
	FetchRowData(ctx context.Context, database, table string, keys [][]byte) (map[string]*nodeRowData, error)
}

// consistencyOptions controls one check run.
type consistencyOptions struct {
	tableFilter   map[string]bool
	includeValues bool
	mismatchCap   int
	timeout       time.Duration
}

// handleClusterConsistency serves GET /admin/cluster/consistency.
//
// Query parameters:
//
//	database      - one database; empty/default = every local database
//	tables        - comma-separated table whitelist
//	include_values- include each node's values for the first differing keys (default true)
//	max_mismatches- differing rows reported per table (default 200, max 1000)
//	timeout_seconds- per-RPC fan-out deadline (default 30, max 300)
//	alive_only    - compare only ALIVE peers (default true; false also tries
//	                SUSPECT/DEAD/LEAVING/JOINING members, recording unreachable ones)
func (h *AdminHandlers) handleClusterConsistency(w http.ResponseWriter, r *http.Request) {
	registry := h.resolveRegistryOrError(w)
	if registry == nil {
		return
	}

	q := r.URL.Query()
	opts := consistencyOptions{
		includeValues: q.Get("include_values") != "false",
		mismatchCap:   consistencyDefaultMismatch,
		timeout:       consistencyDefaultTimeout,
	}
	if raw := q.Get("max_mismatches"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeErrorResponse(w, http.StatusBadRequest, "max_mismatches must be a positive integer")
			return
		}
		if n > consistencyMaxMismatch {
			n = consistencyMaxMismatch
		}
		opts.mismatchCap = n
	}
	if raw := q.Get("timeout_seconds"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeErrorResponse(w, http.StatusBadRequest, "timeout_seconds must be a positive integer")
			return
		}
		opts.timeout = time.Duration(n) * time.Second
		if opts.timeout > consistencyMaxTimeout {
			opts.timeout = consistencyMaxTimeout
		}
	}
	if raw := q.Get("tables"); strings.TrimSpace(raw) != "" {
		opts.tableFilter = make(map[string]bool)
		for _, name := range strings.Split(raw, ",") {
			if name = strings.TrimSpace(name); name != "" {
				opts.tableFilter[name] = true
			}
		}
	}
	aliveOnly := q.Get("alive_only") != "false"

	targets, nodeDescs, unreachable := h.buildConsistencyTargets(registry, aliveOnly)

	database := strings.TrimSpace(q.Get("database"))
	var databases []string
	if database != "" {
		databases = []string{database}
	} else {
		databases = h.dbManager.ListDatabases()
		sort.Strings(databases)
	}

	ctx, cancel := context.WithTimeout(r.Context(), opts.timeout)
	defer cancel()

	localNodeID := registry.GetLocalNodeID()
	report := map[string]interface{}{
		"local_node_id": localNodeID,
		"checked_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"parameters": map[string]interface{}{
			"database":       database,
			"tables":         q.Get("tables"),
			"include_values": opts.includeValues,
			"max_mismatches": opts.mismatchCap,
			"alive_only":     aliveOnly,
		},
		"nodes":     nodeDescs,
		"databases": h.checkAllDatabases(ctx, targets, databases, opts),
	}

	consistent, complete := summarizeConsistency(report["databases"].([]map[string]interface{}))
	if len(unreachable) > 0 {
		// An eligible member this run could not contact is not evidence of
		// divergence, but it does make the verdict partial.
		complete = false
	}
	report["unreachable_nodes"] = unreachable
	report["consistent"] = consistent
	report["complete"] = complete
	if !consistent {
		// Header must be set before WriteHeader; writeJSONResponse sets it
		// again, harmlessly, when it encodes the body.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
	}
	writeJSONResponse(w, report, false, "")
}

// buildConsistencyTargets assembles the local fetcher and one fetcher per
// eligible member, alongside each member's descriptor and a list of
// eligible members that could not be contacted (so the caller can mark the
// run partial rather than silently compare a subset of the membership).
func (h *AdminHandlers) buildConsistencyTargets(registry *marmotgrpc.NodeRegistry, aliveOnly bool) ([]consistencyFetcher, []map[string]interface{}, []map[string]interface{}) {
	localNodeID := registry.GetLocalNodeID()
	members := registry.GetMembershipInfo()

	targets := []consistencyFetcher{&localConsistencyFetcher{nodeID: localNodeID, dbMgr: h.dbManager}}
	descs := []map[string]interface{}{}
	unreachable := []map[string]interface{}{}

	for _, m := range members {
		isLocal := m.NodeID == localNodeID
		desc := map[string]interface{}{
			"node_id":  m.NodeID,
			"address":  m.Address,
			"status":   m.Status,
			"is_local": isLocal,
		}
		if isLocal {
			descs = append(descs, desc)
			continue
		}
		if aliveOnly && m.Status != marmotgrpc.NodeStatus_ALIVE.String() {
			continue
		}
		if h.client == nil {
			// No peer client wired (embedded/test use): report the member
			// as a target the run cannot reach rather than silently drop it.
			desc["unreachable_reason"] = "peer client not configured"
			descs = append(descs, desc)
			unreachable = append(unreachable, map[string]interface{}{
				"node_id": m.NodeID, "reason": "peer client not configured",
			})
			continue
		}
		peerClient, err := h.client.GetClient(m.NodeID)
		if err != nil {
			desc["unreachable_reason"] = err.Error()
			descs = append(descs, desc)
			unreachable = append(unreachable, map[string]interface{}{
				"node_id": m.NodeID, "reason": err.Error(),
			})
			continue
		}
		targets = append(targets, &remoteConsistencyFetcher{nodeID: m.NodeID, client: peerClient})
		descs = append(descs, desc)
	}

	return targets, descs, unreachable
}

// checkAllDatabases runs the comparison for each requested database
// independently: one database's absent node or RPC failure never aborts the
// others.
func (h *AdminHandlers) checkAllDatabases(ctx context.Context, targets []consistencyFetcher, databases []string, opts consistencyOptions) []map[string]interface{} {
	reports := make([]map[string]interface{}, 0, len(databases))
	for _, database := range databases {
		reports = append(reports, h.checkOneDatabase(ctx, database, targets, opts))
	}
	return reports
}

// checkOneDatabase gathers digests from every target, then compares table
// by table.
func (h *AdminHandlers) checkOneDatabase(ctx context.Context, database string, targets []consistencyFetcher, opts consistencyOptions) map[string]interface{} {
	digests := make([]map[string]*digestInfo, len(targets))
	dbAbsent := make([]bool, len(targets))
	nodeErrors := make([]string, len(targets))

	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t consistencyFetcher) {
			defer wg.Done()
			d, absent, err := t.FetchDigests(ctx, database)
			if err != nil {
				nodeErrors[i] = err.Error()
				return
			}
			digests[i] = d
			dbAbsent[i] = absent
		}(i, t)
	}
	wg.Wait()

	tableSet := map[string]bool{}
	for i, d := range digests {
		if nodeErrors[i] != "" || dbAbsent[i] {
			continue
		}
		for name := range d {
			tableSet[name] = true
		}
	}
	tables := make([]string, 0, len(tableSet))
	for name := range tableSet {
		if opts.tableFilter == nil || opts.tableFilter[name] {
			tables = append(tables, name)
		}
	}
	sort.Strings(tables)

	tableReports := make([]map[string]interface{}, 0, len(tables))
	dbConsistent, dbComplete := true, true

	for _, table := range tables {
		tr := h.compareTable(ctx, database, table, targets, digests, dbAbsent, nodeErrors, opts)
		tableReports = append(tableReports, tr)
		if tr["status"] != "equal" {
			dbConsistent = false
		}
		if tr["status"] == "error" {
			dbComplete = false
		}
		if v, _ := tr["mismatches_truncated"].(bool); v {
			dbComplete = false
		}
	}

	// The database itself missing on some nodes, or a digest RPC failure,
	// is a cluster-level inconsistency for this database.
	absentNodes := []uint64{}
	errNodes := []map[string]interface{}{}
	for i, t := range targets {
		if dbAbsent[i] {
			absentNodes = append(absentNodes, t.NodeID())
		}
		if nodeErrors[i] != "" {
			errNodes = append(errNodes, map[string]interface{}{
				"node_id": t.NodeID(),
				"error":   nodeErrors[i],
			})
		}
	}
	if len(absentNodes) > 0 || len(errNodes) > 0 {
		dbConsistent = false
	}
	if len(errNodes) > 0 {
		dbComplete = false
	}

	return map[string]interface{}{
		"database":          database,
		"consistent":        dbConsistent,
		"complete":          dbComplete,
		"tables":            tableReports,
		"missing_on_nodes":  absentNodes,
		"node_errors":       errNodes,
		"tables_not_listed": filteredMissing(opts.tableFilter, tableSet),
	}
}

// filteredMissing reports whitelisted table names that no node reported a
// digest for (typo, or the table exists nowhere), so a silent empty result
// cannot be mistaken for a successful check.
func filteredMissing(filter map[string]bool, present map[string]bool) []string {
	if filter == nil {
		return nil
	}
	var missing []string
	for name := range filter {
		if !present[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

// compareTable compares one table across nodes: presence, schema, then (if
// digests disagree) row-level hashes and optional values.
func (h *AdminHandlers) compareTable(
	ctx context.Context,
	database, table string,
	targets []consistencyFetcher,
	digests []map[string]*digestInfo,
	dbAbsent []bool,
	nodeErrors []string,
	opts consistencyOptions,
) map[string]interface{} {
	tr := map[string]interface{}{
		"table":            table,
		"missing_db_nodes": []uint64{},
	}

	presentNodes := []int{}
	missingNodes := []uint64{}
	for i, t := range targets {
		if nodeErrors[i] != "" {
			// Digest stage failed for this node: it cannot be compared.
			tr["status"] = "error"
			return tr
		}
		if dbAbsent[i] {
			tr["missing_db_nodes"] = append(tr["missing_db_nodes"].([]uint64), t.NodeID())
			missingNodes = append(missingNodes, t.NodeID())
			continue
		}
		if d, ok := digests[i][table]; ok && d != nil {
			presentNodes = append(presentNodes, i)
		} else {
			missingNodes = append(missingNodes, t.NodeID())
		}
	}
	tr["missing_on_nodes"] = missingNodes

	digestEntries := make([]map[string]interface{}, 0, len(presentNodes))
	for _, i := range presentNodes {
		d := digests[i][table]
		digestEntries = append(digestEntries, map[string]interface{}{
			"node_id":       targets[i].NodeID(),
			"row_count":     d.rowCount,
			"hash":          fmt.Sprintf("%016x", d.hash),
			"signature":     d.signature,
			"primary_key":   d.primaryKey,
			"without_rowid": d.withoutRowID,
		})
	}
	tr["digests"] = digestEntries

	if len(presentNodes) == 0 {
		tr["status"] = "missing_table"
		return tr
	}
	if len(missingNodes) > 0 {
		// Table absence is itself the finding; row comparison cannot add to it.
		tr["status"] = "missing_table"
		return tr
	}

	// Schema divergence: group present nodes by column signature.
	sigGroups := map[string][]uint64{}
	for _, i := range presentNodes {
		sig := digests[i][table].signature
		sigGroups[sig] = append(sigGroups[sig], targets[i].NodeID())
	}
	if len(sigGroups) > 1 {
		groups := make([]map[string]interface{}, 0, len(sigGroups))
		for sig, nodes := range sigGroups {
			sort.Slice(nodes, func(a, b int) bool { return nodes[a] < nodes[b] })
			groups = append(groups, map[string]interface{}{
				"signature": sig,
				"nodes":     nodes,
			})
		}
		sort.Slice(groups, func(a, b int) bool {
			return groups[a]["signature"].(string) < groups[b]["signature"].(string)
		})
		tr["status"] = "schema_mismatch"
		tr["schema_groups"] = groups
		return tr
	}

	// Same schema: equal only if every node's content hash agrees.
	first := digests[presentNodes[0]][table]
	allEqual := true
	for _, i := range presentNodes[1:] {
		if digests[i][table].hash != first.hash || digests[i][table].rowCount != first.rowCount {
			allEqual = false
			break
		}
	}
	tr["primary_key"] = first.primaryKey
	if allEqual {
		tr["status"] = "equal"
		return tr
	}
	tr["status"] = "mismatch"

	// Content differs: pull every node's (key, hash) pages and diff keys.
	mismatches, truncated, rowErr := h.diffTableRows(ctx, database, table, targets, presentNodes, opts)
	if rowErr != nil {
		tr["status"] = "error"
		tr["error"] = rowErr.Error()
		return tr
	}
	tr["mismatch_count"] = len(mismatches)
	tr["mismatches_truncated"] = truncated
	tr["mismatches"] = mismatches
	return tr
}

// diffTableRows pages through every compared node's row hashes, joins on
// the primary-key bytes, and returns the keys that are missing somewhere or
// hash differently, with values attached for the first valueCap of them.
func (h *AdminHandlers) diffTableRows(
	ctx context.Context,
	database, table string,
	targets []consistencyFetcher,
	presentNodes []int,
	opts consistencyOptions,
) ([]map[string]interface{}, bool, error) {
	collected := make([]rowHashCollection, len(targets))
	truncated := false

	var wg sync.WaitGroup
	for _, i := range presentNodes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rows, scanTruncated, err := h.collectNodeRowHashes(ctx, targets[i], database, table)
			collected[i] = rowHashCollection{rows: rows, truncated: scanTruncated, err: err}
		}(i)
	}
	wg.Wait()

	for _, i := range presentNodes {
		if collected[i].err != nil {
			return nil, false, fmt.Errorf("node %d: %w", targets[i].NodeID(), collected[i].err)
		}
		if collected[i].truncated {
			truncated = true
		}
	}

	// Union of keys, keeping one representative rendering per key.
	keySet := map[string]bool{}
	keyText := map[string]string{}
	for _, i := range presentNodes {
		for k, rh := range collected[i].rows {
			keySet[k] = true
			if _, ok := keyText[k]; !ok {
				keyText[k] = rh.keyText
			}
		}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool { return keyText[keys[a]] < keyText[keys[b]] })

	mismatches := make([]map[string]interface{}, 0, opts.mismatchCap)
	valueCandidateKeys := [][]byte{}
	valueKeySet := map[string]bool{}
	capped := false

	for _, k := range keys {
		perNode := make([]map[string]interface{}, 0, len(presentNodes))
		presentHere := 0
		var commonHash uint64
		hashDiffer := false
		first := true
		for _, i := range presentNodes {
			rh, ok := collected[i].rows[k]
			entry := map[string]interface{}{"node_id": targets[i].NodeID(), "present": ok}
			if ok {
				presentHere++
				entry["hash"] = fmt.Sprintf("%016x", rh.hash)
				if first {
					commonHash = rh.hash
					first = false
				} else if rh.hash != commonHash {
					hashDiffer = true
				}
			}
			perNode = append(perNode, entry)
		}

		kind := "value_mismatch"
		if presentHere != len(presentNodes) {
			kind = "missing_row"
		} else if !hashDiffer {
			continue // same key, same row hash on every node: equal
		}

		if len(mismatches) >= opts.mismatchCap {
			capped = true
			break
		}
		entry := map[string]interface{}{
			"key_text": keyText[k],
			"kind":     kind,
			"nodes":    perNode,
		}
		mismatches = append(mismatches, entry)

		if opts.includeValues && len(valueCandidateKeys) < consistencyValueCap {
			if !valueKeySet[k] {
				valueKeySet[k] = true
				valueCandidateKeys = append(valueCandidateKeys, []byte(k))
			}
		}
	}

	truncated = truncated || capped

	if opts.includeValues && len(valueCandidateKeys) > 0 {
		h.attachRowValues(ctx, database, table, targets, presentNodes, collected, mismatches, valueCandidateKeys)
	}

	return mismatches, truncated, nil
}

// collectNodeRowHashes pages through one node's whole row-hash stream for a
// table, bounded by consistencyMaxRowPages. A scan stopped by the cap sets
// the truncated flag rather than failing: the comparison still reports what
// it found, but the run is marked incomplete.
func (h *AdminHandlers) collectNodeRowHashes(ctx context.Context, t consistencyFetcher, database, table string) (map[string]nodeRowHash, bool, error) {
	out := map[string]nodeRowHash{}
	var after []byte
	for page := 0; page < consistencyMaxRowPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		rows, next, hasMore, err := t.FetchRowHashes(ctx, database, table, after)
		if err != nil {
			return nil, false, err
		}
		for _, rh := range rows {
			out[string(rh.keyBytes)] = rh
		}
		if !hasMore || len(next) == 0 {
			return out, false, nil
		}
		after = next
	}
	return out, true, nil
}

// attachRowValues fetches each compared node's values for the first
// differing keys and merges them into that key's per-node entries. Each
// node is asked with the key bytes that node itself produced.
func (h *AdminHandlers) attachRowValues(
	ctx context.Context,
	database, table string,
	targets []consistencyFetcher,
	presentNodes []int,
	collected []rowHashCollection,
	mismatches []map[string]interface{},
	keys [][]byte,
) {
	// Map key byte string back to each node's own encoding of the same key
	// (deterministic msgpack, hence identical - but never assume it).
	type valueResult struct {
		data map[string]*nodeRowData
		err  error
	}
	results := make([]valueResult, len(targets))
	var wg sync.WaitGroup
	for _, i := range presentNodes {
		nodeKeys := make([][]byte, 0, len(keys))
		for _, k := range keys {
			if _, ok := collected[i].rows[string(k)]; ok {
				nodeKeys = append(nodeKeys, collected[i].rows[string(k)].keyBytes)
			}
		}
		if len(nodeKeys) == 0 {
			continue
		}
		wg.Add(1)
		go func(i int, nodeKeys [][]byte) {
			defer wg.Done()
			data, err := targets[i].FetchRowData(ctx, database, table, nodeKeys)
			results[i] = valueResult{data: data, err: err}
		}(i, nodeKeys)
	}
	wg.Wait()

	byText := map[string]map[string]interface{}{}
	for _, m := range mismatches {
		byText[m["key_text"].(string)] = m
	}

	for _, i := range presentNodes {
		if results[i].err != nil {
			continue // values are explanatory only; a failure must not drop the finding
		}
		for k, rd := range results[i].data {
			text, ok := lookupKeyText(collected[i].rows, k)
			if !ok {
				continue
			}
			m, ok := byText[text]
			if !ok {
				continue
			}
			nodes := m["nodes"].([]map[string]interface{})
			for _, n := range nodes {
				if n["node_id"] == targets[i].NodeID() {
					n["values"] = rd.values
					n["present"] = rd.present
				}
			}
		}
	}
}

func lookupKeyText(rows map[string]nodeRowHash, key string) (string, bool) {
	if rh, ok := rows[key]; ok {
		return rh.keyText, true
	}
	return "", false
}

// summarizeConsistency folds the per-database reports into the top-level
// verdict: consistent only when every database compared fully and cleanly,
// complete only when no node failed part of the run.
func summarizeConsistency(dbs []map[string]interface{}) (consistent bool, complete bool) {
	consistent, complete = true, true
	for _, db := range dbs {
		if c, _ := db["consistent"].(bool); !c {
			consistent = false
		}
		if c, _ := db["complete"].(bool); !c {
			complete = false
		}
	}
	return consistent, complete
}

// ---- fetchers ----

// localConsistencyFetcher reads this node directly, bypassing the gRPC
// stack for the node answering the admin call.
type localConsistencyFetcher struct {
	nodeID uint64
	dbMgr  *db.DatabaseManager
}

func (f *localConsistencyFetcher) NodeID() uint64 { return f.nodeID }

func (f *localConsistencyFetcher) FetchDigests(ctx context.Context, database string) (map[string]*digestInfo, bool, error) {
	mdb, err := f.dbMgr.GetDatabase(database)
	if err != nil {
		if errors.Is(err, db.ErrDatabaseDetached) {
			return nil, false, fmt.Errorf("database detached: %w", err)
		}
		return nil, false, fmt.Errorf("local database unavailable: %w", err)
	}
	digests, err := mdb.ConsistencyDigests(ctx)
	if err != nil {
		return nil, false, err
	}
	out := make(map[string]*digestInfo, len(digests))
	for i := range digests {
		d := &digests[i]
		out[d.Table] = &digestInfo{
			primaryKey:   d.PrimaryKey,
			columns:      d.Columns,
			signature:    db.ConsistencyColumnSignature(d.Columns),
			rowCount:     d.RowCount,
			hash:         d.Hash,
			withoutRowID: d.WithoutRowID,
		}
	}
	return out, false, nil
}

func (f *localConsistencyFetcher) FetchRowHashes(ctx context.Context, database, table string, afterKey []byte) ([]nodeRowHash, []byte, bool, error) {
	mdb, err := f.dbMgr.GetDatabase(database)
	if err != nil {
		return nil, nil, false, err
	}
	var after []interface{}
	if len(afterKey) > 0 {
		if err := encoding.UnmarshalStrict(afterKey, &after); err != nil {
			return nil, nil, false, fmt.Errorf("decode after key: %w", err)
		}
	}
	rows, next, hasMore, err := mdb.ConsistencyRowHashes(ctx, table, after, consistencyRowPageSize)
	if err != nil {
		return nil, nil, false, err
	}
	return encodeRowHashes(rows, next, hasMore)
}

func (f *localConsistencyFetcher) FetchRowData(ctx context.Context, database, table string, keys [][]byte) (map[string]*nodeRowData, error) {
	mdb, err := f.dbMgr.GetDatabase(database)
	if err != nil {
		return nil, err
	}
	tuples, err := decodeKeyTuples(keys)
	if err != nil {
		return nil, err
	}
	rows, err := mdb.ConsistencyRowsByKeys(ctx, table, tuples)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*nodeRowData, len(rows))
	for i, row := range rows {
		values := map[string]string{}
		for _, v := range row.Values {
			values[v.Name] = v.Value
		}
		out[string(keys[i])] = &nodeRowData{present: row.Present, values: values}
	}
	return out, nil
}

// remoteConsistencyFetcher reads a peer over gRPC.
type remoteConsistencyFetcher struct {
	nodeID uint64
	client marmotgrpc.MarmotServiceClient
}

func (f *remoteConsistencyFetcher) NodeID() uint64 { return f.nodeID }

func (f *remoteConsistencyFetcher) FetchDigests(ctx context.Context, database string) (map[string]*digestInfo, bool, error) {
	resp, err := f.client.GetTableDigests(ctx, &marmotgrpc.ConsistencyDigestRequest{
		RequestingNodeId: f.nodeID,
		Database:         database,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("get table digests: %w", err)
	}
	out := make(map[string]*digestInfo, len(resp.GetTables()))
	for _, t := range resp.GetTables() {
		cols := make([]db.ConsistencyColumn, 0, len(t.GetColumns()))
		for _, c := range t.GetColumns() {
			cols = append(cols, db.ConsistencyColumn{Name: c.GetName(), Type: c.GetType()})
		}
		out[t.GetTable()] = &digestInfo{
			primaryKey:   t.GetPrimaryKeyColumns(),
			columns:      cols,
			signature:    db.ConsistencyColumnSignature(cols),
			rowCount:     int64(t.GetRowCount()),
			hash:         t.GetHash(),
			withoutRowID: t.GetWithoutRowid(),
		}
	}
	return out, false, nil
}

func (f *remoteConsistencyFetcher) FetchRowHashes(ctx context.Context, database, table string, afterKey []byte) ([]nodeRowHash, []byte, bool, error) {
	resp, err := f.client.GetRowHashes(ctx, &marmotgrpc.ConsistencyRowHashRequest{
		RequestingNodeId: f.nodeID,
		Database:         database,
		Table:            table,
		AfterKey:         afterKey,
		Limit:            consistencyRowPageSize,
	})
	if err != nil {
		return nil, nil, false, err
	}
	out := make([]nodeRowHash, 0, len(resp.GetRows()))
	for _, r := range resp.GetRows() {
		out = append(out, nodeRowHash{keyBytes: r.GetKey(), keyText: r.GetKeyText(), hash: r.GetHash()})
	}
	return out, resp.GetNextAfterKey(), resp.GetHasMore(), nil
}

func (f *remoteConsistencyFetcher) FetchRowData(ctx context.Context, database, table string, keys [][]byte) (map[string]*nodeRowData, error) {
	resp, err := f.client.GetRowData(ctx, &marmotgrpc.ConsistencyRowDataRequest{
		RequestingNodeId: f.nodeID,
		Database:         database,
		Table:            table,
		Keys:             keys,
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]*nodeRowData, len(resp.GetRows()))
	for _, r := range resp.GetRows() {
		out[string(r.GetKey())] = &nodeRowData{present: r.GetPresent(), values: r.GetValues()}
	}
	return out, nil
}

// ---- shared encoding helpers ----

func encodeRowHashes(rows []db.ConsistencyRowHash, next []interface{}, hasMore bool) ([]nodeRowHash, []byte, bool, error) {
	out := make([]nodeRowHash, 0, len(rows))
	for _, r := range rows {
		raw, err := encoding.Marshal(r.Key)
		if err != nil {
			return nil, nil, false, fmt.Errorf("encode row key: %w", err)
		}
		out = append(out, nodeRowHash{keyBytes: raw, keyText: db.ConsistencyRenderKey(r.Key), hash: r.Hash})
	}
	var nextBytes []byte
	if hasMore && len(next) > 0 {
		raw, err := encoding.Marshal(next)
		if err != nil {
			return nil, nil, false, fmt.Errorf("encode next key: %w", err)
		}
		nextBytes = raw
	}
	return out, nextBytes, hasMore, nil
}

func decodeKeyTuples(raw [][]byte) ([][]interface{}, error) {
	out := make([][]interface{}, len(raw))
	for i, b := range raw {
		var key []interface{}
		if err := encoding.UnmarshalStrict(b, &key); err != nil {
			return nil, fmt.Errorf("decode key %d: %w", i, err)
		}
		out[i] = key
	}
	return out, nil
}
