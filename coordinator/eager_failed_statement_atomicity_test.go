//go:build sqlite_preupdate_hook
// +build sqlite_preupdate_hook

package coordinator_test

// End-to-end pinning for statement-level atomicity inside an explicit
// transaction (the "order + its items must both land or neither does"
// requirement): when a statement fails mid-way and SQLite rolls the whole
// statement back, its preupdate-hook captures are discarded too, so COMMIT
// cannot replay rows the failed statement never made.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExplicitTransactionFailedStatementIsAtomic drives the order/items
// shape: one statement writes the order, a multi-row items statement fails
// on its second row (NOT NULL) and is aborted wholesale, a corrected items
// statement succeeds, then COMMIT. Only the successful changes may land and
// replicate; the failed statement's first row must not.
func TestExplicitTransactionFailedStatementIsAtomic(t *testing.T) {
	s := setupNoopDML(t)

	for _, q := range []string{
		"CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT NOT NULL)",
		"CREATE TABLE order_items (id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL, qty INTEGER NOT NULL)",
	} {
		_, err := s.handler.HandleQuery(s.session, q, nil)
		require.NoError(t, err)
	}

	_, err := s.handler.HandleQuery(s.session, "BEGIN", nil)
	require.NoError(t, err)

	// The order lands.
	_, err = s.handler.HandleQuery(s.session, "INSERT INTO orders (id, status) VALUES (100, 'pending')", nil)
	require.NoError(t, err)

	// Items statement: first row is fine, second violates NOT NULL; SQLite
	// aborts the whole statement and rolls the first item row back.
	_, err = s.handler.HandleQuery(s.session,
		"INSERT INTO order_items (id, order_id, qty) VALUES (1, 100, 2), (2, 100, NULL)", nil)
	require.Error(t, err, "the malformed items statement must be rejected")
	require.True(t, s.session.InTransaction(), "a plain statement error must not end the transaction")

	// The failed statement's row must be invisible even inside the open txn.
	res, err := s.handler.HandleQuery(s.session, "SELECT COUNT(*) FROM order_items WHERE id = 1", nil)
	require.NoError(t, err)
	require.Equal(t, int64(0), res.Rows[0][0], "aborted item must be gone inside the transaction")

	// Corrected items statement succeeds; the action can still complete.
	_, err = s.handler.HandleQuery(s.session, "INSERT INTO order_items (id, order_id, qty) VALUES (10, 100, 3)", nil)
	require.NoError(t, err)

	_, err = s.handler.HandleQuery(s.session, "COMMIT", nil)
	require.NoError(t, err)

	var orders, failedItems, goodItems int
	require.NoError(t, s.conn.QueryRow("SELECT COUNT(*) FROM orders WHERE id = 100").Scan(&orders))
	require.Equal(t, 1, orders, "the order must commit")
	require.NoError(t, s.conn.QueryRow("SELECT COUNT(*) FROM order_items WHERE id = 1").Scan(&failedItems))
	require.Zero(t, failedItems, "the failed items statement's rolled-back row must never land")
	require.NoError(t, s.conn.QueryRow("SELECT COUNT(*) FROM order_items WHERE id = 10").Scan(&goodItems))
	require.Equal(t, 1, goodItems, "the corrected items statement must commit")
}

// TestExplicitTransactionFailureFollowedByRollbackAppliesNothing verifies the
// other half: after a failed statement, an explicit ROLLBACK discards the
// earlier successful statement too - nothing lands or replicates from the
// transaction.
func TestExplicitTransactionFailureFollowedByRollbackAppliesNothing(t *testing.T) {
	s := setupNoopDML(t)

	_, err := s.handler.HandleQuery(s.session, "CREATE TABLE orders2 (id INTEGER PRIMARY KEY, status TEXT NOT NULL)", nil)
	require.NoError(t, err)

	commitsBefore := s.replicator.commits

	_, err = s.handler.HandleQuery(s.session, "BEGIN", nil)
	require.NoError(t, err)
	_, err = s.handler.HandleQuery(s.session, "INSERT INTO orders2 (id, status) VALUES (100, 'pending')", nil)
	require.NoError(t, err)
	_, err = s.handler.HandleQuery(s.session, "INSERT INTO orders2 (id, status) VALUES (101, NULL)", nil)
	require.Error(t, err)
	_, err = s.handler.HandleQuery(s.session, "ROLLBACK", nil)
	require.NoError(t, err)

	var count int
	require.NoError(t, s.conn.QueryRow("SELECT COUNT(*) FROM orders2").Scan(&count))
	require.Zero(t, count, "ROLLBACK must leave none of the transaction's changes behind")
	require.Equal(t, commitsBefore, s.replicator.commits, "a rolled-back transaction must not replicate")
}
