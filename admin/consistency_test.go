package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/maxpert/marmot/db"
	"github.com/maxpert/marmot/encoding"
	marmotgrpc "github.com/maxpert/marmot/grpc"
	"github.com/maxpert/marmot/hlc"
	"github.com/stretchr/testify/require"
)

// fakeConsistencyNode is an in-memory node for the coordinator's
// classification logic: canned digests, row hashes and values, with real
// msgpack key encoding and real keyset pagination.
type fakeConsistencyNode struct {
	id        uint64
	absent    map[string]bool
	tables    map[string]map[string]*digestInfo // database -> table
	rows      map[string]map[uint64]uint64      // "database|table" -> id -> row hash
	vals      map[string]map[uint64]map[string]string
	digestErr map[string]error
}

func (f *fakeConsistencyNode) NodeID() uint64 { return f.id }

func (f *fakeConsistencyNode) FetchDigests(_ context.Context, database string) (map[string]*digestInfo, bool, error) {
	if f.digestErr != nil && f.digestErr[database] != nil {
		return nil, false, f.digestErr[database]
	}
	if f.absent[database] {
		return nil, true, nil
	}
	return f.tables[database], false, nil
}

func (f *fakeConsistencyNode) FetchRowHashes(_ context.Context, database, table string, afterKey []byte) ([]nodeRowHash, []byte, bool, error) {
	var after int64
	if len(afterKey) > 0 {
		var tuple []interface{}
		if err := encoding.UnmarshalStrict(afterKey, &tuple); err != nil {
			return nil, nil, false, err
		}
		after = tuple[0].(int64)
	}
	ids := make([]uint64, 0)
	for id := range f.rows[database+"|"+table] {
		if int64(id) > after {
			ids = append(ids, id)
		}
	}
	// uint64 sort
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if ids[j] < ids[i] {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
	const page = 2
	hasMore := len(ids) > page
	if hasMore {
		ids = ids[:page]
	}
	out := make([]nodeRowHash, 0, len(ids))
	for _, id := range ids {
		out = append(out, nodeRowHash{keyBytes: fakeKeyBytes(id), keyText: fmt.Sprintf("i:%d", id), hash: f.rows[database+"|"+table][id]})
	}
	var next []byte
	if hasMore {
		next = fakeKeyBytes(ids[len(ids)-1])
	}
	return out, next, hasMore, nil
}

func (f *fakeConsistencyNode) FetchRowData(_ context.Context, database, table string, keys [][]byte) (map[string]*nodeRowData, error) {
	out := map[string]*nodeRowData{}
	for _, raw := range keys {
		var tuple []interface{}
		if err := encoding.UnmarshalStrict(raw, &tuple); err != nil {
			return nil, err
		}
		id := tuple[0].(int64)
		rd := &nodeRowData{present: false}
		if values, ok := f.vals[database+"|"+table][uint64(id)]; ok {
			rd.present = true
			rd.values = values
		}
		out[string(raw)] = rd
	}
	return out, nil
}

func fakeKeyBytes(id uint64) []byte {
	raw, err := encoding.Marshal([]interface{}{int64(id)})
	if err != nil {
		panic(err)
	}
	return raw
}

var fakeColumns = []db.ConsistencyColumn{{Name: "id", Type: "INTEGER"}, {Name: "v", Type: "TEXT"}}

func fakeTableDigest(rowHashes map[uint64]uint64) *digestInfo {
	// Table hash just needs to be unequal whenever the row-hash set is; a
	// cheap xor-sum over rows stands in for the real FNV digest here, where
	// the coordinator's classification is what is under test.
	var h uint64 = 1469598103934665603
	for id, rh := range rowHashes {
		h ^= rh ^ id
		h *= 1099511628211
	}
	return &digestInfo{
		primaryKey: []string{"id"},
		columns:    fakeColumns,
		signature:  db.ConsistencyColumnSignature(fakeColumns),
		rowCount:   int64(len(rowHashes)),
		hash:       h,
	}
}

func fakeRows(ids []uint64, valueHash uint64) map[uint64]uint64 {
	m := map[uint64]uint64{}
	for _, id := range ids {
		m[id] = valueHash ^ id
	}
	return m
}

func fakeValues(id uint64, v string) map[string]string {
	return map[string]string{"id": fmt.Sprintf("i:%d", id), "v": "s:" + v}
}

// consistencyCluster builds n identical nodes (ids 1..n) with three rows.
func consistencyCluster(t *testing.T, n int, opts consistencyOptions) (*AdminHandlers, []*fakeConsistencyNode, []consistencyFetcher) {
	t.Helper()
	nodes := make([]*fakeConsistencyNode, 0, n)
	fetchers := make([]consistencyFetcher, 0, n)
	for i := 1; i <= n; i++ {
		rows := fakeRows([]uint64{1, 2, 3}, 1000)
		node := &fakeConsistencyNode{
			id:     uint64(i),
			absent: map[string]bool{},
			tables: map[string]map[string]*digestInfo{
				"app": {"t": fakeTableDigest(rows)},
			},
			rows: map[string]map[uint64]uint64{"app|t": rows},
			vals: map[string]map[uint64]map[string]string{
				"app|t": {
					1: fakeValues(1, "alice"),
					2: fakeValues(2, "bob"),
					3: fakeValues(3, "carol"),
				},
			},
		}
		nodes = append(nodes, node)
		fetchers = append(fetchers, node)
	}
	return &AdminHandlers{}, nodes, fetchers
}

func defaultConsistencyOpts() consistencyOptions {
	return consistencyOptions{includeValues: true, mismatchCap: consistencyDefaultMismatch, timeout: 0}
}

func tableReport(t *testing.T, dbReport map[string]interface{}, table string) map[string]interface{} {
	t.Helper()
	for _, tr := range dbReport["tables"].([]map[string]interface{}) {
		if tr["table"] == table {
			return tr
		}
	}
	t.Fatalf("table %s missing from report: %v", table, dbReport["tables"])
	return nil
}

// TestConsistencyOrchestratorAllEqual: identical nodes report equal and
// consistent, and never fetch row-level detail.
func TestConsistencyOrchestratorAllEqual(t *testing.T) {
	h, _, fetchers := consistencyCluster(t, 3, defaultConsistencyOpts())
	rep := h.checkOneDatabase(context.Background(), "app", fetchers, defaultConsistencyOpts())
	require.True(t, rep["consistent"].(bool))
	require.True(t, rep["complete"].(bool))
	tr := tableReport(t, rep, "t")
	require.Equal(t, "equal", tr["status"])
	require.Empty(t, tr["mismatches"])
	require.Empty(t, rep["node_errors"])
}

// TestConsistencyOrchestratorValueMismatch: one node holding a different
// value for id=2 produces exactly one value_mismatch finding naming node 2,
// with each node's actual value attached.
func TestConsistencyOrchestratorValueMismatch(t *testing.T) {
	h, nodes, fetchers := consistencyCluster(t, 3, defaultConsistencyOpts())

	// Node 2 diverges row 2: flip its hash and value.
	rows2 := fakeRows([]uint64{1, 2, 3}, 1000)
	rows2[2] = rows2[2] ^ 0xdeadbeef
	nodes[1].rows["app|t"] = rows2
	nodes[1].tables["app"]["t"] = fakeTableDigest(rows2)
	nodes[1].vals["app|t"][2] = fakeValues(2, "BOB")

	rep := h.checkOneDatabase(context.Background(), "app", fetchers, defaultConsistencyOpts())
	require.False(t, rep["consistent"].(bool))
	tr := tableReport(t, rep, "t")
	require.Equal(t, "mismatch", tr["status"])
	mismatches := tr["mismatches"].([]map[string]interface{})
	require.Len(t, mismatches, 1)
	m := mismatches[0]
	require.Equal(t, "i:2", m["key_text"])
	require.Equal(t, "value_mismatch", m["kind"])

	perNode := m["nodes"].([]map[string]interface{})
	require.Len(t, perNode, 3)
	byNode := map[uint64]map[string]interface{}{}
	for _, n := range perNode {
		byNode[n["node_id"].(uint64)] = n
	}
	for _, id := range []uint64{1, 2, 3} {
		require.True(t, byNode[id]["present"].(bool))
		require.NotEmpty(t, byNode[id]["hash"])
	}
	require.Equal(t, "s:BOB", byNode[2]["values"].(map[string]string)["v"])
	require.Equal(t, "s:bob", byNode[1]["values"].(map[string]string)["v"])
}

// TestConsistencyOrchestratorMissingRow: a row absent on one node is
// classified missing_row with that node marked present=false.
func TestConsistencyOrchestratorMissingRow(t *testing.T) {
	h, nodes, fetchers := consistencyCluster(t, 2, defaultConsistencyOpts())

	rows2 := fakeRows([]uint64{1, 2}, 1000) // node 2 is missing row 3
	nodes[1].rows["app|t"] = rows2
	nodes[1].tables["app"]["t"] = fakeTableDigest(rows2)
	delete(nodes[1].vals["app|t"], 3)

	rep := h.checkOneDatabase(context.Background(), "app", fetchers, defaultConsistencyOpts())
	tr := tableReport(t, rep, "t")
	require.Equal(t, "mismatch", tr["status"])
	mismatches := tr["mismatches"].([]map[string]interface{})
	require.Len(t, mismatches, 1)
	m := mismatches[0]
	require.Equal(t, "i:3", m["key_text"])
	require.Equal(t, "missing_row", m["kind"])
	perNode := m["nodes"].([]map[string]interface{})
	present := map[uint64]bool{}
	for _, n := range perNode {
		present[n["node_id"].(uint64)] = n["present"].(bool)
	}
	require.True(t, present[1])
	require.False(t, present[2])
}

// TestConsistencyOrchestratorMissingTable: table absent on one node is
// reported as missing_table naming the node, without row fetching.
func TestConsistencyOrchestratorMissingTable(t *testing.T) {
	h, nodes, fetchers := consistencyCluster(t, 2, defaultConsistencyOpts())
	delete(nodes[1].tables["app"], "t")

	rep := h.checkOneDatabase(context.Background(), "app", fetchers, defaultConsistencyOpts())
	require.False(t, rep["consistent"].(bool))
	tr := tableReport(t, rep, "t")
	require.Equal(t, "missing_table", tr["status"])
	require.Equal(t, []uint64{2}, tr["missing_on_nodes"])
}

// TestConsistencyOrchestratorSchemaMismatch: differing column signatures
// are reported as schema groups rather than a content diff.
func TestConsistencyOrchestratorSchemaMismatch(t *testing.T) {
	h, nodes, fetchers := consistencyCluster(t, 2, defaultConsistencyOpts())
	otherCols := []db.ConsistencyColumn{{Name: "id", Type: "INTEGER"}, {Name: "v", Type: "TEXT"}, {Name: "extra", Type: "INTEGER"}}
	nodes[1].tables["app"]["t"].columns = otherCols
	nodes[1].tables["app"]["t"].signature = db.ConsistencyColumnSignature(otherCols)

	rep := h.checkOneDatabase(context.Background(), "app", fetchers, defaultConsistencyOpts())
	tr := tableReport(t, rep, "t")
	require.Equal(t, "schema_mismatch", tr["status"])
	groups := tr["schema_groups"].([]map[string]interface{})
	require.Len(t, groups, 2)
}

// TestConsistencyOrchestratorMissingDatabaseAndNodeError.
func TestConsistencyOrchestratorMissingDatabaseAndNodeError(t *testing.T) {
	h, nodes, fetchers := consistencyCluster(t, 3, defaultConsistencyOpts())

	// Node 2 lacks the whole database; node 3's digest RPC fails.
	nodes[1].absent["app"] = true
	nodes[2].digestErr = map[string]error{"app": fmt.Errorf("connection refused")}

	rep := h.checkOneDatabase(context.Background(), "app", fetchers, defaultConsistencyOpts())
	require.False(t, rep["consistent"].(bool))
	require.False(t, rep["complete"].(bool))
	require.Equal(t, []uint64{2}, rep["missing_on_nodes"])
	errs := rep["node_errors"].([]map[string]interface{})
	require.Len(t, errs, 1)
	require.Equal(t, uint64(3), errs[0]["node_id"])
}

// TestConsistencyOrchestratorMismatchCap: more divergent rows than the cap
// reports only cap findings and signals truncation, so the run cannot be
// read as a complete match.
func TestConsistencyOrchestratorMismatchCap(t *testing.T) {
	h, nodes, fetchers := consistencyCluster(t, 2, defaultConsistencyOpts())

	// Five rows on node 1, none on node 2: five missing rows, cap at two.
	rows1 := fakeRows([]uint64{1, 2, 3, 4, 5}, 1000)
	nodes[0].rows["app|t"] = rows1
	nodes[0].tables["app"]["t"] = fakeTableDigest(rows1)
	rows2 := map[uint64]uint64{}
	nodes[1].rows["app|t"] = rows2
	nodes[1].tables["app"]["t"] = fakeTableDigest(rows2)

	opts := defaultConsistencyOpts()
	opts.mismatchCap = 2
	opts.includeValues = false
	rep := h.checkOneDatabase(context.Background(), "app", fetchers, opts)
	tr := tableReport(t, rep, "t")
	require.Equal(t, "mismatch", tr["status"])
	require.Len(t, tr["mismatches"].([]map[string]interface{}), 2)
	require.True(t, tr["mismatches_truncated"].(bool))
	require.False(t, rep["complete"].(bool))
}

// TestConsistencyOrchestratorTableFilterWhitelist: only requested tables
// are compared, and a whitelisted name present nowhere is surfaced rather
// than silently ignored.
func TestConsistencyOrchestratorTableFilterWhitelist(t *testing.T) {
	h, _, fetchers := consistencyCluster(t, 2, defaultConsistencyOpts())
	opts := defaultConsistencyOpts()
	opts.tableFilter = map[string]bool{"t": true, "ghost": true}

	rep := h.checkOneDatabase(context.Background(), "app", fetchers, opts)
	require.Len(t, rep["tables"].([]map[string]interface{}), 1)
	require.Equal(t, []string{"ghost"}, rep["tables_not_listed"])
}

// TestConsistencyOrchestratorPagination: fake pages two rows at a time; a
// three-row divergent set still classifies every row.
func TestConsistencyOrchestratorPagination(t *testing.T) {
	h, nodes, fetchers := consistencyCluster(t, 2, defaultConsistencyOpts())
	rows2 := fakeRows([]uint64{1, 2}, 1000)
	nodes[1].rows["app|t"] = rows2
	nodes[1].tables["app"]["t"] = fakeTableDigest(rows2)

	rep := h.checkOneDatabase(context.Background(), "app", fetchers, defaultConsistencyOpts())
	tr := tableReport(t, rep, "t")
	mismatches := tr["mismatches"].([]map[string]interface{})
	require.Len(t, mismatches, 1)
	require.Equal(t, "i:3", mismatches[0]["key_text"])
}

// serveConsistencyHTTP dispatches a request through a chi router mounting
// the same route the production mux does, with auth disabled (no cluster
// secret in tests).
func serveConsistencyHTTP(h *AdminHandlers, target string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.Get("/admin/cluster/consistency", h.handleClusterConsistency)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

// TestConsistencyEndpointLocalEndToEnd runs the real handler against a real
// local DatabaseManager (single-node cluster) and verifies the response
// envelope: 200, consistent, one equal table named explicitly.
func TestConsistencyEndpointLocalEndToEnd(t *testing.T) {
	server, err := marmotgrpc.NewServer(marmotgrpc.ServerConfig{NodeID: 1, Address: "127.0.0.1", Port: 0})
	require.NoError(t, err)

	dm, err := db.NewDatabaseManager(t.TempDir(), 1, hlc.NewClock(1))
	require.NoError(t, err)
	t.Cleanup(func() { _ = dm.Close() })
	require.NoError(t, dm.CreateDatabase("app"))
	mdb, err := dm.GetDatabase("app")
	require.NoError(t, err)
	_, err = mdb.GetWriteDB().Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`)
	require.NoError(t, err)
	_, err = mdb.GetWriteDB().Exec(`INSERT INTO t (id, v) VALUES (1, 'alice'), (2, 'bob')`)
	require.NoError(t, err)

	h := NewAdminHandlers(server, dm)
	rr := serveConsistencyHTTP(h, "/admin/cluster/consistency?database=app")
	require.Equal(t, http.StatusOK, rr.Code)

	var resp struct {
		Data struct {
			Consistent bool   `json:"consistent"`
			Complete   bool   `json:"complete"`
			LocalID    uint64 `json:"local_node_id"`
			Databases  []struct {
				Database   string                   `json:"database"`
				Consistent bool                     `json:"consistent"`
				Tables     []map[string]interface{} `json:"tables"`
			} `json:"databases"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.True(t, resp.Data.Consistent)
	require.True(t, resp.Data.Complete)
	require.Equal(t, uint64(1), resp.Data.LocalID)
	require.Len(t, resp.Data.Databases, 1)
	require.True(t, resp.Data.Databases[0].Consistent)
	require.Equal(t, "t", resp.Data.Databases[0].Tables[0]["table"])
	require.Equal(t, "equal", resp.Data.Databases[0].Tables[0]["status"])
}

// TestConsistencyEndpointBadRequest exercises the HTTP parameter
// validation without a live cluster.
func TestConsistencyEndpointBadRequest(t *testing.T) {
	server, err := marmotgrpc.NewServer(marmotgrpc.ServerConfig{NodeID: 1, Address: "127.0.0.1", Port: 0})
	require.NoError(t, err)
	h := NewAdminHandlers(server, nil)

	rr := serveConsistencyHTTP(h, "/admin/cluster/consistency?max_mismatches=nope")
	require.Equal(t, 400, rr.Code)

	rr = serveConsistencyHTTP(h, "/admin/cluster/consistency?timeout_seconds=-3")
	require.Equal(t, 400, rr.Code)
}
