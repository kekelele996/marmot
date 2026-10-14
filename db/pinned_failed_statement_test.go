//go:build sqlite_preupdate_hook
// +build sqlite_preupdate_hook

package db

import (
	"context"
	"testing"

	"github.com/maxpert/marmot/encoding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturedEntryIDs decodes the id column of every captured intent entry.
func capturedEntryIDs(t *testing.T, entries []*IntentEntry) map[int64]bool {
	t.Helper()
	ids := make(map[int64]bool, len(entries))
	for _, e := range entries {
		var id int64
		require.NoError(t, encoding.Unmarshal(e.NewValues["id"], &id))
		ids[id] = true
	}
	return ids
}

// commitCapturedEntries simulates what handleCommit does with a pinned
// session's captures: release (roll back) the pinned SQLite transaction, then
// replay the captured CDC entries into the real database.
func commitCapturedEntries(t *testing.T, source *ReplicatedDatabase, sess *pinnedHookSession) {
	t.Helper()
	entries := sess.session.CapturedIntentEntries()
	require.NoError(t, sess.Release())
	if len(entries) > 0 {
		require.NoError(t, source.ApplyCDCEntries(entries))
	}
}

func persistedIDs(t *testing.T, source *ReplicatedDatabase) []int64 {
	t.Helper()
	rows, err := source.GetWriteDB().Query("SELECT id FROM test ORDER BY id")
	require.NoError(t, err)
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	return ids
}

// TestPinnedSession_FailedMultiRowInsertDoesNotLeakCDC is the order/items
// case from the issue: a multi-row INSERT whose second row hits a duplicate
// key is aborted wholesale by SQLite, but the preupdate hook still fired for
// the first (rolled-back) row. That ghost capture must not ride the next
// successful statement into COMMIT, or the failed statement's row lands even
// though the statement failed - a half-applied action.
func TestPinnedSession_FailedMultiRowInsertDoesNotLeakCDC(t *testing.T) {
	source := newRowidTestDatabase(t, 1)
	require.NoError(t, execAndReload(source, `CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`))

	ctx := context.Background()
	sess, err := source.BeginPinnedSession(ctx, 20077)
	require.NoError(t, err)
	pinned := sess.(*pinnedHookSession)

	// statement 1: succeeds
	_, _, err = sess.ExecuteStatement(ctx, "INSERT INTO test (id, name) VALUES (1, 'order')", nil)
	require.NoError(t, err)

	// statement 2: first row would be fine, second row duplicates id=1;
	// SQLite ABORT rolls the whole statement back (id=2 disappears).
	_, _, err = sess.ExecuteStatement(ctx, "INSERT INTO test (id, name) VALUES (2, 'item'), (1, 'dup')", nil)
	require.Error(t, err)

	cols, rows, qerr := sess.Query(ctx, "SELECT COUNT(*) AS c FROM test WHERE id = 2", nil)
	require.NoError(t, qerr)
	_ = cols
	assert.Equal(t, int64(0), rows[0]["c"], "failed statement's row must not exist inside the open transaction either")

	// statement 3: succeeds
	_, _, err = sess.ExecuteStatement(ctx, "INSERT INTO test (id, name) VALUES (3, 'after')", nil)
	require.NoError(t, err)

	entries := pinned.session.CapturedIntentEntries()
	require.Len(t, entries, 2, "only the two successful statements' rows may be captured")
	ids := capturedEntryIDs(t, entries)
	assert.Equal(t, map[int64]bool{1: true, 3: true}, ids)

	commitCapturedEntries(t, source, pinned)
	assert.Equal(t, []int64{1, 3}, persistedIDs(t, source))
}

// TestPinnedSession_FailedUpdateDoesNotLeakCDC covers an UPDATE that aborts
// on a UNIQUE collision: the hook fired for the changed row, but the rolled
// back UPDATE must not survive among the committed captures.
func TestPinnedSession_FailedUpdateDoesNotLeakCDC(t *testing.T) {
	source := newRowidTestDatabase(t, 1)
	require.NoError(t, execAndReload(source, `CREATE TABLE test (id INTEGER PRIMARY KEY, u TEXT NOT NULL UNIQUE)`))

	ctx := context.Background()
	sess, err := source.BeginPinnedSession(ctx, 20078)
	require.NoError(t, err)
	pinned := sess.(*pinnedHookSession)

	_, _, err = sess.ExecuteStatement(ctx, "INSERT INTO test (id, u) VALUES (1, 'a'), (2, 'b'), (3, 'c')", nil)
	require.NoError(t, err)

	// Move row 2 onto row 1's unique value: SQLite aborts and rolls the
	// single-row change back, but the preupdate hook captured the UPDATE.
	_, _, err = sess.ExecuteStatement(ctx, "UPDATE test SET u = 'a' WHERE id = 2", nil)
	require.Error(t, err)

	// A valid update afterwards captures only its own row.
	_, _, err = sess.ExecuteStatement(ctx, "UPDATE test SET u = 'd' WHERE id = 3", nil)
	require.NoError(t, err)

	entries := pinned.session.CapturedIntentEntries()
	var updates []int64
	var inserts []int64
	for _, e := range entries {
		var id int64
		require.NoError(t, encoding.Unmarshal(e.NewValues["id"], &id))
		switch e.Operation {
		case uint8(OpTypeInsert):
			inserts = append(inserts, id)
		case uint8(OpTypeUpdate):
			updates = append(updates, id)
		}
	}
	assert.ElementsMatch(t, []int64{1, 2, 3}, inserts)
	assert.Equal(t, []int64{3}, updates, "the failed UPDATE of id=2 must not leak")

	commitCapturedEntries(t, source, pinned)

	gotRows, err := source.GetWriteDB().Query("SELECT id, u FROM test ORDER BY id")
	require.NoError(t, err)
	defer gotRows.Close()
	type kv struct {
		id int64
		u  string
	}
	var got []kv
	for gotRows.Next() {
		var v kv
		require.NoError(t, gotRows.Scan(&v.id, &v.u))
		got = append(got, v)
	}
	require.Equal(t, []kv{{1, "a"}, {2, "b"}, {3, "d"}}, got)
}

// TestPinnedSession_FirstStatementFailureThenSuccess proves the transaction
// stays usable after its FIRST statement fails, and none of the failed
// statement's captures survive.
func TestPinnedSession_FirstStatementFailureThenSuccess(t *testing.T) {
	source := newRowidTestDatabase(t, 1)
	require.NoError(t, execAndReload(source, `CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`))

	ctx := context.Background()
	sess, err := source.BeginPinnedSession(ctx, 20079)
	require.NoError(t, err)
	pinned := sess.(*pinnedHookSession)

	// Failing first statement (NOT NULL on name).
	_, _, err = sess.ExecuteStatement(ctx, "INSERT INTO test (id, name) VALUES (1, NULL)", nil)
	require.Error(t, err)

	_, _, err = sess.ExecuteStatement(ctx, "INSERT INTO test (id, name) VALUES (2, 'ok')", nil)
	require.NoError(t, err)

	ids := capturedEntryIDs(t, pinned.session.CapturedIntentEntries())
	assert.Equal(t, map[int64]bool{2: true}, ids)

	commitCapturedEntries(t, source, pinned)
	assert.Equal(t, []int64{2}, persistedIDs(t, source))
}

// TestPinnedSession_FailedStatementThenRollbackProvesAllOrNothing verifies
// that after a mid-transaction failure followed by explicit ROLLBACK, none of
// the transaction's changes land - the "all fail" half of the guarantee.
func TestPinnedSession_FailedStatementThenRollbackProvesAllOrNothing(t *testing.T) {
	source := newRowidTestDatabase(t, 1)
	require.NoError(t, execAndReload(source, `CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`))

	ctx := context.Background()
	sess, err := source.BeginPinnedSession(ctx, 20080)
	require.NoError(t, err)

	_, _, err = sess.ExecuteStatement(ctx, "INSERT INTO test (id, name) VALUES (1, 'order')", nil)
	require.NoError(t, err)
	_, _, err = sess.ExecuteStatement(ctx, "INSERT INTO test (id, name) VALUES (2, 'x'), (1, 'dup')", nil)
	require.Error(t, err)

	// Explicit rollback discards the whole pinned transaction.
	require.NoError(t, sess.Release())

	assert.Equal(t, []int64(nil), persistedIDs(t, source))
}

// TestPinnedSession_FailedStatementWithSpilledCaptures forces every captured
// row into the persistent CDC segment log (tiny in-memory budget) and checks
// the failed statement's rows are excluded from the segment manifest, the
// PREPARE row accounting and the post-seal read path - not just from session
// memory.
func TestPinnedSession_FailedStatementWithSpilledCaptures(t *testing.T) {
	source := newRowidTestDatabase(t, 1)
	require.NoError(t, execAndReload(source, `CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`))

	ctx := context.Background()
	sess, err := source.BeginPinnedSession(ctx, 20081)
	require.NoError(t, err)
	pinned := sess.(*pinnedHookSession)
	// Force the overflow-to-segment path from the first capture.
	pinned.session.captureMu.Lock()
	pinned.session.capturedRowsMax = 1
	pinned.session.captureMu.Unlock()

	const txnID uint64 = 20081

	_, _, err = sess.ExecuteStatement(ctx, "INSERT INTO test (id, name) VALUES (1, 'order')", nil)
	require.NoError(t, err)
	_, _, err = sess.ExecuteStatement(ctx, "INSERT INTO test (id, name) VALUES (2, 'x'), (1, 'dup')", nil)
	require.Error(t, err)
	_, _, err = sess.ExecuteStatement(ctx, "INSERT INTO test (id, name) VALUES (3, 'after')", nil)
	require.NoError(t, err)

	// PREPARE's PreparedPayload.Rows comes from currentPayload: the failed
	// statement's rows must not count toward it.
	pebbleStore, ok := source.metaStore.(*PebbleMetaStore)
	require.True(t, ok, "test database uses the pebble meta store")
	if rows, pending := pebbleStore.cdcLog.pendingRowCount(txnID); pending {
		assert.Equal(t, uint64(2), rows, "failed statement's rows must not count toward the prepare payload")
	} else {
		t.Fatal("expected a pending CDC manifest for the spilled txn")
	}

	// After sealing (as DurablyPrepareTransaction does), the persisted read
	// path used by local commit and log replay sees exactly the surviving rows.
	require.NoError(t, source.metaStore.SealCapturedRows(txnID))
	cursor, err := source.metaStore.IterateCapturedRows(txnID)
	require.NoError(t, err)
	sealedIDs := map[int64]bool{}
	for cursor.Next() {
		_, data := cursor.Row()
		row, derr := DecodeRow(data)
		require.NoError(t, derr)
		var id int64
		require.NoError(t, encoding.Unmarshal(row.NewValues["id"], &id))
		sealedIDs[id] = true
	}
	require.NoError(t, cursor.Err())
	require.NoError(t, cursor.Close())
	assert.Equal(t, map[int64]bool{1: true, 3: true}, sealedIDs)

	require.NoError(t, sess.Release())
}
