package db

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/maxpert/marmot/common"
)

// ConsistencyRowIDKey is the synthetic primary key column reported for a
// rowid table that declares no PRIMARY KEY: its rows are identified and
// ordered by SQLite's rowid. It can never collide with a real column name
// because client DDL is refused the double-underscore "marmot" namespaces;
// leading double underscore alone is legal for clients, so keep the name
// distinctive enough for operators reading a mismatch report.
const ConsistencyRowIDKey = "__rowid__"

// Consistency default/limits for row-hash paging. They bound one RPC's
// memory; the admin check pages until a table is fully compared or its own
// mismatch cap is reached.
const (
	ConsistencyDefaultPageSize = 1024
	ConsistencyMaxPageSize     = 8192
	// ConsistencyMaxKeysPerFetch bounds one GetRowData request: the values
	// exist only to explain the first few mismatches, never to resync data.
	ConsistencyMaxKeysPerFetch = 256
)

// ConsistencyColumn describes one column in storage order.
type ConsistencyColumn struct {
	Name string
	Type string // Declared SQLite type, "" for a typeless column.
}

// ConsistencyTableDigest is one user table's local content digest: enough
// for nodes to agree (or disagree) on the table without exchanging rows.
type ConsistencyTableDigest struct {
	Table        string
	PrimaryKey   []string // Declared PK columns in key order; {ConsistencyRowIDKey} for a keyless rowid table.
	WithoutRowID bool
	Columns      []ConsistencyColumn
	RowCount     int64
	Hash         uint64 // FNV-1a 64 over the schema header and every row in key order.
}

// ConsistencyRowHash pairs a primary key tuple with the hash of that one
// row's canonical frame. Key element types are the driver's own: int64,
// float64, string, []byte.
type ConsistencyRowHash struct {
	Key  []interface{}
	Hash uint64
}

// ConsistencyValue is one fetched cell in column storage order.
type ConsistencyValue struct {
	Name  string
	Value string // Deterministic rendering, see ConsistencyRenderValue.
}

// ConsistencyRowValues is one requested primary key's answer: Present
// reports whether the row exists; Values carries the row when it does.
type ConsistencyRowValues struct {
	Key     []interface{}
	Present bool
	Values  []ConsistencyValue
}

// ConsistencyDigests returns the digests of every replicated user table in
// the database, sorted by table name. Marmot's own internal tables
// (__marmot__*), SQLite shadow tables (sqlite_*) and virtual tables are
// excluded: they are protocol state or derived artefacts, not client data
// that should be compared node to node.
//
// The scan is read-only and streams rows; it does not take a snapshot that
// coordinates with other nodes, so a check run while writes are in flight
// can report a transient difference.
func (mdb *ReplicatedDatabase) ConsistencyDigests(ctx context.Context) ([]ConsistencyTableDigest, error) {
	tables, err := mdb.consistencyUserTables(ctx)
	if err != nil {
		return nil, err
	}

	digests := make([]ConsistencyTableDigest, 0, len(tables))
	for _, table := range tables {
		digest, err := mdb.consistencyTableDigest(ctx, table.name, table.createSQL)
		if err != nil {
			return nil, fmt.Errorf("digest table %s: %w", table.name, err)
		}
		digests = append(digests, digest)
	}
	return digests, nil
}

// ConsistencyRowHashes returns one ordered page of (key, row hash) pairs
// for table starting strictly after after (empty/nil means the first
// page), nextAfter the key a following page starts after, and hasMore.
// limit <= 0 uses ConsistencyDefaultPageSize; larger values are capped.
func (mdb *ReplicatedDatabase) ConsistencyRowHashes(
	ctx context.Context,
	table string,
	after []interface{},
	limit int,
) (rows []ConsistencyRowHash, nextAfter []interface{}, hasMore bool, err error) {
	meta, err := mdb.consistencyTableMeta(ctx, table)
	if err != nil {
		return nil, nil, false, err
	}
	pageLimit := normalizePageSize(limit)

	query, args, err := buildRowHashQuery(meta, after, pageLimit)
	if err != nil {
		return nil, nil, false, err
	}

	rs, err := mdb.GetReadDB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, false, fmt.Errorf("query row hashes for %s: %w", table, err)
	}
	defer rs.Close()

	got := make([]ConsistencyRowHash, 0, pageLimit)
	for rs.Next() {
		dest := make([]interface{}, len(meta.selects))
		for i := range dest {
			dest[i] = new(interface{})
		}
		if err := rs.Scan(dest...); err != nil {
			return nil, nil, false, fmt.Errorf("scan row hash for %s: %w", table, err)
		}
		values := make([]interface{}, len(dest))
		for i := range dest {
			values[i] = *(dest[i].(*interface{}))
		}
		key := meta.keyValues(values)
		got = append(got, ConsistencyRowHash{
			Key:  key,
			Hash: fnv64(meta.rowFrame(values)),
		})
	}
	if err := rs.Err(); err != nil {
		return nil, nil, false, fmt.Errorf("iterate row hashes for %s: %w", table, err)
	}

	if len(got) > pageLimit {
		hasMore = true
		got = got[:pageLimit]
	}
	if len(got) > 0 {
		nextAfter = got[len(got)-1].Key
	}
	return got, nextAfter, hasMore, nil
}

// ConsistencyRowsByKeys returns the rendered rows of table at keys in the
// requested order, marking absent ones. At most ConsistencyMaxKeysPerFetch
// keys are served per call.
func (mdb *ReplicatedDatabase) ConsistencyRowsByKeys(ctx context.Context, table string, keys [][]interface{}) ([]ConsistencyRowValues, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	if len(keys) > ConsistencyMaxKeysPerFetch {
		return nil, fmt.Errorf("at most %d keys per request, got %d", ConsistencyMaxKeysPerFetch, len(keys))
	}

	meta, err := mdb.consistencyTableMeta(ctx, table)
	if err != nil {
		return nil, err
	}

	out := make([]ConsistencyRowValues, 0, len(keys))
	for _, key := range keys {
		if len(key) != len(meta.keyColumns) {
			return nil, fmt.Errorf("table %s key has %d values, expected %d", table, len(key), len(meta.keyColumns))
		}
		row := ConsistencyRowValues{Key: key}

		query, args := buildKeyLookupQuery(meta)
		rs, err := mdb.GetReadDB().QueryContext(ctx, query, args(key)...)
		if err != nil {
			return nil, fmt.Errorf("query row in %s: %w", table, err)
		}
		if rs.Next() {
			dest := make([]interface{}, len(meta.selects))
			for i := range dest {
				dest[i] = new(interface{})
			}
			if err := rs.Scan(dest...); err != nil {
				rs.Close()
				return nil, fmt.Errorf("scan row in %s: %w", table, err)
			}
			values := make([]interface{}, len(dest))
			for i := range dest {
				values[i] = *(dest[i].(*interface{}))
			}
			row.Present = true
			row.Values = meta.renderValues(values)
		}
		if err := rs.Err(); err != nil {
			rs.Close()
			return nil, fmt.Errorf("iterate row in %s: %w", table, err)
		}
		rs.Close()

		out = append(out, row)
	}
	return out, nil
}

// ConsistencyRenderKey renders a primary key tuple the same way cell
// values are rendered: one element renders plainly ("7", "s:alice"), a
// tuple wraps in parentheses ("(1, s:alice)").
func ConsistencyRenderKey(key []interface{}) string {
	parts := make([]string, len(key))
	for i, v := range key {
		parts[i] = ConsistencyRenderValue(v)
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// ConsistencyRenderValue renders a driver value deterministically and
// unambiguously: NULL, i:<int>, f:<float>, s:<text>, b:<hex blob>. The
// type tag keeps an integer 1 and a text "1" distinguishable, and hex
// keeps a BLOB byte-exact in a JSON report.
func ConsistencyRenderValue(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case int64:
		return "i:" + strconv.FormatInt(x, 10)
	case float64:
		return "f:" + strconv.FormatFloat(x, 'g', -1, 64)
	case bool:
		if x {
			return "i:1"
		}
		return "i:0"
	case string:
		return "s:" + x
	case []byte:
		return "b:" + hex.EncodeToString(x)
	case time.Time:
		return "t:" + x.UTC().Format(time.RFC3339Nano)
	default:
		return "x:" + fmt.Sprintf("%v", x)
	}
}

// ConsistencyColumnSignature is the canonical text compared between nodes
// to tell a schema divergence from a content divergence: column names and
// declared types in storage order.
func ConsistencyColumnSignature(cols []ConsistencyColumn) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = c.Name + ":" + c.Type
	}
	return strings.Join(parts, ",")
}

// ---- internals ----

type userTable struct {
	name      string
	createSQL string
}

// consistencyUserTables lists replicated client tables.
func (mdb *ReplicatedDatabase) consistencyUserTables(ctx context.Context) ([]userTable, error) {
	rs, err := mdb.GetReadDB().QueryContext(ctx,
		`SELECT name, sql FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer rs.Close()

	var tables []userTable
	for rs.Next() {
		var name string
		var createSQL sql.NullString
		if err := rs.Scan(&name, &createSQL); err != nil {
			return nil, fmt.Errorf("scan sqlite_master: %w", err)
		}
		if !consistencyIncludeTable(name, createSQL.String) {
			continue
		}
		tables = append(tables, userTable{name: name, createSQL: createSQL.String})
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("iterate sqlite_master: %w", err)
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].name < tables[j].name })
	return tables, nil
}

// consistencyIncludeTable excludes everything that is not directly
// replicated client data:
//   - sqlite_* shadow tables backing virtual tables;
//   - every __marmot* protocol table. This is deliberately broader than
//     common.IsInternalTableName's literal "__marmot__" prefix: it also
//     covers __marmot_schema_version (single underscore), which the
//     codebase's LIKE filters ('__marmot__%' with '_' a wildcard) exclude
//     in effect. A client table beginning "__marmot" cannot normally exist
//     anyway (protocol DDL refuses the "__marmot__" class);
//   - virtual tables themselves (their storage is engine-defined and their
//     shadow tables are already excluded; row images are not meaningful).
func consistencyIncludeTable(name, createSQL string) bool {
	lowerName := strings.ToLower(name)
	if strings.HasPrefix(lowerName, "sqlite_") || strings.HasPrefix(lowerName, "__marmot") {
		return false
	}
	if common.IsInternalTableName(name) {
		return false
	}
	if strings.HasPrefix(lowerTrimPrefix(createSQL), "create virtual table") {
		return false
	}
	return true
}

func lowerTrimPrefix(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// withoutRowIDPattern matches a trailing WITHOUT ROWID clause. SQLite
// treats the keyword pair as a table-option suffix; checking the suffix
// (rather than a substring) avoids a column default or CHECK expression
// containing the words from misclassifying a table.
var withoutRowIDPattern = regexp.MustCompile(`(?i)\)\s*without\s+rowid\s*$`)

type tableMeta struct {
	table        string
	withoutRow   bool
	columns      []ConsistencyColumn // storage order, hidden virtual-table columns excluded
	keyColumns   []string            // PK column names in key order, or {ConsistencyRowIDKey}
	keyIndexes   []int               // key positions inside select expressions/values
	selects      []string            // quoted select expressions (data columns, plus rowid when synthetic)
	dataColCount int                 // number of real data columns (values before a synthetic rowid)
}

// keyValues extracts the key tuple from a scanned select-values slice.
func (m *tableMeta) keyValues(values []interface{}) []interface{} {
	key := make([]interface{}, len(m.keyIndexes))
	for i, idx := range m.keyIndexes {
		key[i] = values[idx]
	}
	return key
}

// rowFrame builds the canonical frame of one row over EVERY select value:
// a fixed per-table column count means tags alone delimit values, and the
// trailing row marker delimits rows.
func (m *tableMeta) rowFrame(values []interface{}) []byte {
	buf := make([]byte, 0, 64)
	for _, v := range values[:m.dataColCount] {
		buf = appendCanonicalValue(buf, v)
	}
	buf = append(buf, rowMarker)
	return buf
}

// headerFrame folds the schema into the table digest so a content hash can
// only agree when the compared columns and key agree too.
func (m *tableMeta) headerFrame() []byte {
	buf := make([]byte, 0, 64)
	buf = appendUvarint(buf, uint64(len(m.columns)))
	for _, c := range m.columns {
		buf = appendLenString(buf, c.Name)
		buf = appendLenString(buf, c.Type)
	}
	buf = appendUvarint(buf, uint64(len(m.keyColumns)))
	for _, k := range m.keyColumns {
		buf = appendLenString(buf, k)
	}
	return buf
}

func (m *tableMeta) renderValues(values []interface{}) []ConsistencyValue {
	out := make([]ConsistencyValue, len(m.columns))
	for i, c := range m.columns {
		out[i] = ConsistencyValue{Name: c.Name, Value: ConsistencyRenderValue(values[i])}
	}
	return out
}

// xinfoColumn mirrors one row of PRAGMA table_xinfo.
type xinfoColumn struct {
	cid    int
	name   string
	typ    string
	pk     int
	hidden int // 0 normal, 1 hidden (virtual table), 2 virtual generated, 3 stored generated
}

// consistencyTableMeta resolves a table's columns and primary key.
func (mdb *ReplicatedDatabase) consistencyTableMeta(ctx context.Context, table string) (*tableMeta, error) {
	if table == "" || common.IsInternalTableName(table) {
		return nil, fmt.Errorf("refusing to inspect non-user table %q", table)
	}

	rs, err := mdb.GetReadDB().QueryContext(ctx, "PRAGMA table_xinfo("+quoteIdent(table)+")")
	if err != nil {
		return nil, fmt.Errorf("read schema for %s: %w", table, err)
	}
	defer rs.Close()
	var cols []xinfoColumn
	for rs.Next() {
		var (
			cid     int
			name    string
			typ     string
			notnull int
			dflt    sql.NullString
			pk      int
			hidden  int
		)
		if err := rs.Scan(&cid, &name, &typ, &notnull, &dflt, &pk, &hidden); err != nil {
			rs.Close()
			return nil, fmt.Errorf("scan schema for %s: %w", table, err)
		}
		cols = append(cols, xinfoColumn{cid: cid, name: name, typ: typ, pk: pk, hidden: hidden})
	}
	if err := rs.Err(); err != nil {
		rs.Close()
		return nil, fmt.Errorf("iterate schema for %s: %w", table, err)
	}
	rs.Close()
	if len(cols) == 0 {
		return nil, fmt.Errorf("table %s does not exist", table)
	}

	meta := &tableMeta{table: table}
	indexByName := make(map[string]int, len(cols))
	for _, c := range cols {
		if c.hidden == 1 {
			// Hidden columns belong to virtual tables, which consistency
			// excludes; defensively skip them anywhere they appear.
			continue
		}
		indexByName[c.name] = len(meta.columns)
		meta.columns = append(meta.columns, ConsistencyColumn{Name: c.name, Type: c.typ})
		meta.selects = append(meta.selects, quoteIdent(c.name))
	}
	meta.dataColCount = len(meta.columns)

	// PRIMARY KEY columns in pk-index order (PRAGMA's pk field is 1-based).
	pkCols := make([]xinfoColumn, 0)
	for _, c := range cols {
		if c.pk > 0 {
			pkCols = append(pkCols, c)
		}
	}
	sort.Slice(pkCols, func(i, j int) bool { return pkCols[i].pk < pkCols[j].pk })

	if len(pkCols) == 0 {
		meta.keyColumns = []string{ConsistencyRowIDKey}
		meta.selects = append(meta.selects, "rowid")
		meta.keyIndexes = []int{len(meta.selects) - 1}
	} else {
		for _, c := range pkCols {
			idx, ok := indexByName[c.name]
			if !ok {
				return nil, fmt.Errorf("primary key column %q missing from columns of %s", c.name, table)
			}
			meta.keyColumns = append(meta.keyColumns, c.name)
			meta.keyIndexes = append(meta.keyIndexes, idx)
		}
	}

	return meta, nil
}

// consistencyTableDigest computes one table's digest, including whether it
// is WITHOUT ROWID (only needed for the digest report, not key resolution).
func (mdb *ReplicatedDatabase) consistencyTableDigest(ctx context.Context, table, createSQL string) (ConsistencyTableDigest, error) {
	meta, err := mdb.consistencyTableMeta(ctx, table)
	if err != nil {
		return ConsistencyTableDigest{}, err
	}
	meta.withoutRow = withoutRowIDPattern.MatchString(strings.TrimSpace(createSQL))

	h := fnv.New64a()
	if _, err := h.Write(meta.headerFrame()); err != nil {
		return ConsistencyTableDigest{}, err
	}

	var count int64
	query := "SELECT " + strings.Join(meta.selects, ", ") +
		" FROM " + quoteIdent(meta.table) +
		" ORDER BY " + meta.orderBy()
	rs, err := mdb.GetReadDB().QueryContext(ctx, query)
	if err != nil {
		return ConsistencyTableDigest{}, fmt.Errorf("scan %s for digest: %w", table, err)
	}
	defer rs.Close()

	for rs.Next() {
		dest := make([]interface{}, len(meta.selects))
		for i := range dest {
			dest[i] = new(interface{})
		}
		if err := rs.Scan(dest...); err != nil {
			return ConsistencyTableDigest{}, fmt.Errorf("scan %s row: %w", table, err)
		}
		values := make([]interface{}, len(dest))
		for i := range dest {
			values[i] = *(dest[i].(*interface{}))
		}
		if _, err := h.Write(meta.rowFrame(values)); err != nil {
			return ConsistencyTableDigest{}, err
		}
		count++
	}
	if err := rs.Err(); err != nil {
		return ConsistencyTableDigest{}, fmt.Errorf("iterate %s for digest: %w", table, err)
	}

	pk := make([]string, len(meta.keyColumns))
	copy(pk, meta.keyColumns)
	columns := make([]ConsistencyColumn, len(meta.columns))
	copy(columns, meta.columns)

	return ConsistencyTableDigest{
		Table:        meta.table,
		PrimaryKey:   pk,
		WithoutRowID: meta.withoutRow,
		Columns:      columns,
		RowCount:     count,
		Hash:         h.Sum64(),
	}, nil
}

// orderBy returns the deterministic ORDER BY expression list.
func (m *tableMeta) orderBy() string {
	parts := make([]string, len(m.keyColumns))
	for i, k := range m.keyColumns {
		if k == ConsistencyRowIDKey {
			parts[i] = "rowid"
		} else {
			parts[i] = quoteIdent(k)
		}
	}
	return strings.Join(parts, ", ")
}

// keyPredicates returns WHERE predicates comparing the key tuple, each
// placeholder '?'.
func (m *tableMeta) keyPredicates() string {
	parts := make([]string, len(m.keyColumns))
	for i, k := range m.keyColumns {
		if k == ConsistencyRowIDKey {
			parts[i] = "rowid = ?"
		} else {
			parts[i] = quoteIdent(k) + " = ?"
		}
	}
	return strings.Join(parts, " AND ")
}

func buildKeyLookupQuery(m *tableMeta) (query string, args func(key []interface{}) []interface{}) {
	query = "SELECT " + strings.Join(m.selects, ", ") +
		" FROM " + quoteIdent(m.table) +
		" WHERE " + m.keyPredicates() + " LIMIT 1"
	return query, func(key []interface{}) []interface{} { return key }
}

// buildRowHashQuery builds the keyset-paginated scan. SQLite supports the
// row-value comparison "(a, b) > (?, ?)"; the single-column and rowid cases
// use a plain predicate. LIMIT fetches one extra row to signal hasMore.
//
// Known edge: a non-INTEGER PRIMARY KEY on an ordinary rowid table may
// contain NULLs (SQLite quirk), and NULL never satisfies "> ?", so such
// rows can fall outside the keyset scan. The table digest - a full scan -
// still detects the divergence, only the per-record pinpoint can omit
// NULL-keyed rows.
func buildRowHashQuery(m *tableMeta, after []interface{}, limit int) (string, []interface{}, error) {
	var where string
	var args []interface{}
	if len(after) > 0 {
		if len(after) != len(m.keyColumns) {
			return "", nil, fmt.Errorf("after key has %d values, expected %d", len(after), len(m.keyColumns))
		}
		if len(m.keyColumns) == 1 {
			col := m.keyColumns[0]
			if col == ConsistencyRowIDKey {
				col = "rowid"
			} else {
				col = quoteIdent(col)
			}
			where = " WHERE " + col + " > ?"
		} else {
			cols := make([]string, len(m.keyColumns))
			placeholders := make([]string, len(m.keyColumns))
			for i, c := range m.keyColumns {
				cols[i] = quoteIdent(c)
				placeholders[i] = "?"
			}
			where = " WHERE (" + strings.Join(cols, ", ") + ") > (" + strings.Join(placeholders, ", ") + ")"
		}
		args = append(args, after...)
	}

	query := "SELECT " + strings.Join(m.selects, ", ") +
		" FROM " + quoteIdent(m.table) +
		where +
		" ORDER BY " + m.orderBy() +
		" LIMIT " + strconv.Itoa(limit+1)
	return query, args, nil
}

func normalizePageSize(limit int) int {
	if limit <= 0 {
		return ConsistencyDefaultPageSize
	}
	if limit > ConsistencyMaxPageSize {
		return ConsistencyMaxPageSize
	}
	return limit
}

// ---- canonical value framing ----

const (
	tagNull   byte = 0
	tagInt    byte = 'i'
	tagFloat  byte = 'f'
	tagText   byte = 's'
	tagBlob   byte = 'b'
	tagTime   byte = 't'
	tagOther  byte = 'x'
	rowMarker byte = 0x1e
)

func appendCanonicalValue(buf []byte, v interface{}) []byte {
	switch x := v.(type) {
	case nil:
		return append(buf, tagNull)
	case int64:
		buf = append(buf, tagInt)
		return strconv.AppendInt(buf, x, 10)
	case float64:
		buf = append(buf, tagFloat)
		return strconv.AppendFloat(buf, x, 'g', -1, 64)
	case bool:
		buf = append(buf, tagInt)
		if x {
			return append(buf, '1')
		}
		return append(buf, '0')
	case string:
		buf = append(buf, tagText)
		return appendLenString(buf, x)
	case []byte:
		buf = append(buf, tagBlob)
		return appendLenBytes(buf, x)
	case time.Time:
		buf = append(buf, tagTime)
		return appendLenString(buf, x.UTC().Format(time.RFC3339Nano))
	default:
		buf = append(buf, tagOther)
		return appendLenString(buf, fmt.Sprintf("%T:%v", v, v))
	}
}

func appendLenString(buf []byte, s string) []byte {
	buf = appendUvarint(buf, uint64(len(s)))
	return append(buf, s...)
}

func appendLenBytes(buf, b []byte) []byte {
	buf = appendUvarint(buf, uint64(len(b)))
	return append(buf, b...)
}

func appendUvarint(buf []byte, x uint64) []byte {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], x)
	return append(buf, tmp[:n]...)
}

func fnv64(b []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return h.Sum64()
}
