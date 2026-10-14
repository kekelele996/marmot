package db

import (
	"context"
	"strings"
	"testing"

	"github.com/maxpert/marmot/hlc"
	"github.com/stretchr/testify/require"
)

func newConsistencyDBManager(t *testing.T) *DatabaseManager {
	t.Helper()
	dm, err := NewDatabaseManager(t.TempDir(), 1, hlc.NewClock(1))
	require.NoError(t, err)
	t.Cleanup(func() { _ = dm.Close() })
	return dm
}

// setupConsistencySchema creates three user tables covering the key shapes:
// INTEGER PRIMARY KEY, composite WITHOUT ROWID, and a keyless rowid table.
func setupConsistencySchema(t *testing.T, mdb *ReplicatedDatabase) {
	t.Helper()
	stmts := []string{
		`CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			age INTEGER,
			score REAL,
			data BLOB
		)`,
		`CREATE TABLE events (
			kind TEXT NOT NULL,
			ts INTEGER NOT NULL,
			payload TEXT,
			PRIMARY KEY (kind, ts)
		) WITHOUT ROWID`,
		`CREATE TABLE logs (msg TEXT)`,
	}
	for _, stmt := range stmts {
		_, err := mdb.GetWriteDB().Exec(stmt)
		require.NoError(t, err)
	}
	require.NoError(t, mdb.ReloadSchema())
}

func seedConsistencyData(t *testing.T, mdb *ReplicatedDatabase) {
	t.Helper()
	_, err := mdb.GetWriteDB().Exec(`
		INSERT INTO users (id, name, age, score, data) VALUES
			(1, 'alice', 30, 1.5, x'00ff'),
			(2, 'bob', NULL, 2.0, NULL),
			(3, 'carol', 41, -3.25, x'')`)
	require.NoError(t, err)
	_, err = mdb.GetWriteDB().Exec(`
		INSERT INTO events (kind, ts, payload) VALUES
			('click', 100, 'a'), ('click', 200, 'b'), ('view', 150, NULL)`)
	require.NoError(t, err)
	_, err = mdb.GetWriteDB().Exec(`INSERT INTO logs (msg) VALUES ('one'), ('two'), ('three')`)
	require.NoError(t, err)
}

func digestMap(t *testing.T, ctx context.Context, mdb *ReplicatedDatabase) map[string]ConsistencyTableDigest {
	t.Helper()
	digests, err := mdb.ConsistencyDigests(ctx)
	require.NoError(t, err)
	byName := make(map[string]ConsistencyTableDigest, len(digests))
	for _, d := range digests {
		byName[d.Table] = d
	}
	return byName
}

// TestConsistencyDigestsTablesAndKeys: digests list user tables only, in
// name order, with the expected primary key resolution per table shape.
func TestConsistencyDigestsTablesAndKeys(t *testing.T) {
	ctx := context.Background()
	dm := newConsistencyDBManager(t)
	require.NoError(t, dm.CreateDatabase("app"))
	mdb, err := dm.GetDatabase("app")
	require.NoError(t, err)
	setupConsistencySchema(t, mdb)
	seedConsistencyData(t, mdb)

	digests, err := mdb.ConsistencyDigests(ctx)
	require.NoError(t, err)

	var names []string
	for _, d := range digests {
		names = append(names, d.Table)
	}
	require.Equal(t, []string{"events", "logs", "users"}, names, "user tables sorted, protocol tables excluded")

	byName := map[string]ConsistencyTableDigest{}
	for _, d := range digests {
		byName[d.Table] = d
	}
	require.Equal(t, []string{"id"}, byName["users"].PrimaryKey)
	require.Equal(t, []string{"kind", "ts"}, byName["events"].PrimaryKey)
	require.True(t, byName["events"].WithoutRowID)
	require.Equal(t, []string{ConsistencyRowIDKey}, byName["logs"].PrimaryKey)
	require.Equal(t, int64(3), byName["users"].RowCount)
	require.Equal(t, int64(3), byName["events"].RowCount)
	require.Equal(t, int64(3), byName["logs"].RowCount)
	require.NotZero(t, byName["users"].Hash)
}

// TestConsistencyDigestsExcludesVirtualAndInternal: a virtual table, its
// shadow tables, and Marmot protocol tables never appear in digests.
func TestConsistencyDigestsExcludesVirtualAndInternal(t *testing.T) {
	ctx := context.Background()
	dm := newConsistencyDBManager(t)
	require.NoError(t, dm.CreateDatabase("app"))
	mdb, err := dm.GetDatabase("app")
	require.NoError(t, err)

	_, err = mdb.GetWriteDB().Exec(`CREATE TABLE real (id INTEGER PRIMARY KEY, body TEXT)`)
	require.NoError(t, err)
	_, err = mdb.GetWriteDB().Exec(`CREATE VIRTUAL TABLE ft USING fts5(body)`)
	require.NoError(t, err)
	require.NoError(t, mdb.ReloadSchema())

	byName := digestMap(t, ctx, mdb)
	require.Contains(t, byName, "real")
	require.NotContains(t, byName, "ft")
	for name := range byName {
		require.NotContains(t, name, "sqlite_", "shadow table leaked into digests: %s", name)
		require.False(t, strings.HasPrefix(name, "__marmot"),
			"protocol table leaked into digests: %s", name)
	}
}

// TestConsistencyDigestsEqualForIdenticalData: two databases holding the
// same schema and rows produce identical hashes; any row-level change flips
// that table's hash and count independently.
func TestConsistencyDigestsEqualForIdenticalData(t *testing.T) {
	ctx := context.Background()
	dm := newConsistencyDBManager(t)
	require.NoError(t, dm.CreateDatabase("a"))
	require.NoError(t, dm.CreateDatabase("b"))
	a, err := dm.GetDatabase("a")
	require.NoError(t, err)
	b, err := dm.GetDatabase("b")
	require.NoError(t, err)
	setupConsistencySchema(t, a)
	setupConsistencySchema(t, b)
	seedConsistencyData(t, a)
	seedConsistencyData(t, b)

	da := digestMap(t, ctx, a)
	db := digestMap(t, ctx, b)
	for _, table := range []string{"users", "events", "logs"} {
		require.Equal(t, da[table].Hash, db[table].Hash, "identical %s data must hash identically", table)
		require.Equal(t, da[table].RowCount, db[table].RowCount)
	}

	// One row changed on b: users differs, other tables stay equal.
	_, err = b.GetWriteDB().Exec(`UPDATE users SET name = 'ALICE' WHERE id = 1`)
	require.NoError(t, err)
	db = digestMap(t, ctx, b)
	require.NotEqual(t, da["users"].Hash, db["users"].Hash)
	require.Equal(t, da["events"].Hash, db["events"].Hash)
	require.Equal(t, da["logs"].Hash, db["logs"].Hash)

	// An extra row flips count and hash.
	_, err = b.GetWriteDB().Exec(`INSERT INTO users (id, name) VALUES (9, 'extra')`)
	require.NoError(t, err)
	db = digestMap(t, ctx, b)
	require.Equal(t, int64(4), db["users"].RowCount)
	require.NotEqual(t, da["users"].Hash, db["users"].Hash)
}

// TestConsistencyRowHashesPaginationAndOrdering pages through all three key
// shapes with a tiny page and verifies deterministic key order, stable
// continuation, and that a single-row change flips only that row's hash.
func TestConsistencyRowHashesPaginationAndOrdering(t *testing.T) {
	ctx := context.Background()
	dm := newConsistencyDBManager(t)
	require.NoError(t, dm.CreateDatabase("a"))
	require.NoError(t, dm.CreateDatabase("b"))
	a, _ := dm.GetDatabase("a")
	b, _ := dm.GetDatabase("b")
	setupConsistencySchema(t, a)
	setupConsistencySchema(t, b)
	seedConsistencyData(t, a)
	seedConsistencyData(t, b)

	collect := func(mdb *ReplicatedDatabase, table string) map[string]uint64 {
		out := map[string]uint64{}
		var order []string
		var after []interface{}
		for {
			rows, next, hasMore, err := mdb.ConsistencyRowHashes(ctx, table, after, 2)
			require.NoError(t, err)
			for _, r := range rows {
				key := ConsistencyRenderKey(r.Key)
				out[key] = r.Hash
				order = append(order, key)
			}
			if !hasMore {
				break
			}
			require.NotEmpty(t, next)
			after = next
		}
		require.Equal(t, 3, len(order))
		return out
	}

	// users ordered by INTEGER PK.
	ua := collect(a, "users")
	ub := collect(b, "users")
	require.Equal(t, ua, ub)

	// Change row id=1 on b: only that key's hash moves.
	_, err := b.GetWriteDB().Exec(`UPDATE users SET age = 31 WHERE id = 1`)
	require.NoError(t, err)
	ub = collect(b, "users")
	require.Equal(t, ua["i:2"], ub["i:2"])
	require.Equal(t, ua["i:3"], ub["i:3"])
	require.NotEqual(t, ua["i:1"], ub["i:1"])

	// Composite WITHOUT ROWID key, lexicographic (kind, ts) order.
	ea := collect(a, "events")
	eb := collect(b, "events")
	require.Equal(t, ea, eb)
	require.Contains(t, ea, "(s:click, i:100)")
	require.Len(t, ea, 3)

	// Keyless rowid table: keys render as integer rowids.
	la := collect(a, "logs")
	require.Len(t, la, 3)
	for k := range la {
		require.Regexp(t, `^i:\d+$`, k)
	}

	// Invalid continuation arity is rejected.
	_, _, _, err = a.ConsistencyRowHashes(ctx, "events", []interface{}{"only-one"}, 2)
	require.Error(t, err)
}

// TestConsistencyRowsByKeys fetches present and absent rows, including the
// deterministic rendering of every storage type.
func TestConsistencyRowsByKeys(t *testing.T) {
	ctx := context.Background()
	dm := newConsistencyDBManager(t)
	require.NoError(t, dm.CreateDatabase("app"))
	mdb, _ := dm.GetDatabase("app")
	setupConsistencySchema(t, mdb)
	seedConsistencyData(t, mdb)

	rows, err := mdb.ConsistencyRowsByKeys(ctx, "users", [][]interface{}{{int64(1)}, {int64(2)}, {int64(99)}})
	require.NoError(t, err)
	require.Len(t, rows, 3)

	require.True(t, rows[0].Present)
	require.False(t, rows[2].Present)
	require.Nil(t, rows[2].Values)

	values := map[string]string{}
	for _, v := range rows[0].Values {
		values[v.Name] = v.Value
	}
	require.Equal(t, "i:1", values["id"])
	require.Equal(t, "s:alice", values["name"])
	require.Equal(t, "i:30", values["age"])
	require.Equal(t, "f:1.5", values["score"])
	require.Equal(t, "b:00ff", values["data"])

	bob := map[string]string{}
	for _, v := range rows[1].Values {
		bob[v.Name] = v.Value
	}
	require.Equal(t, "NULL", bob["age"])
	require.Equal(t, "NULL", bob["data"])

	// Composite key lookup.
	ev, err := mdb.ConsistencyRowsByKeys(ctx, "events", [][]interface{}{{"click", int64(200)}})
	require.NoError(t, err)
	require.True(t, ev[0].Present)

	// Key arity mismatch rejected.
	_, err = mdb.ConsistencyRowsByKeys(ctx, "events", [][]interface{}{{"click"}})
	require.Error(t, err)

	// Unknown table rejected.
	_, err = mdb.ConsistencyRowsByKeys(ctx, "nope", [][]interface{}{{int64(1)}})
	require.Error(t, err)
}

// TestConsistencyRenderValueDocuments the rendering contract other layers
// (gRPC, admin JSON) rely on.
func TestConsistencyRenderValue(t *testing.T) {
	require.Equal(t, "NULL", ConsistencyRenderValue(nil))
	require.Equal(t, "i:-7", ConsistencyRenderValue(int64(-7)))
	require.Equal(t, "f:1.25", ConsistencyRenderValue(float64(1.25)))
	require.Equal(t, "s:hi", ConsistencyRenderValue("hi"))
	require.Equal(t, "b:0a0b", ConsistencyRenderValue([]byte{0x0a, 0x0b}))
}
