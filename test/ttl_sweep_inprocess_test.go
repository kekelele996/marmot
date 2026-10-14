//go:build sqlite_preupdate_hook
// +build sqlite_preupdate_hook

package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/maxpert/marmot/cfg"
	"github.com/maxpert/marmot/coordinator"
	"github.com/maxpert/marmot/db"
	"github.com/maxpert/marmot/protocol"
	"github.com/maxpert/marmot/ttl"
	"github.com/stretchr/testify/require"
)

// inprocMembership adapts the in-process cluster's fixedNodeProvider to the
// membership view the TTL sweeper elects its owner from.
type inprocMembership struct {
	c     *inprocCluster
	local uint64
}

func (m *inprocMembership) LocalNodeID() uint64 { return m.local }

func (m *inprocMembership) AliveNodeIDs() []uint64 {
	ids, err := m.c.provider.GetAliveNodes()
	if err != nil {
		return nil
	}
	return ids
}

// coordinatorHandler builds a full CoordinatorHandler on a node of an in-process
// cluster: the same HandleQuery write path a MySQL client uses, over the real
// WriteCoordinator/fanout pair.
func (c *inprocCluster) coordinatorHandler(t *testing.T, nodeID uint64) *coordinator.CoordinatorHandler {
	t.Helper()
	n := c.nodes[nodeID]
	readCoord := coordinator.NewReadCoordinator(
		nodeID, c.provider, db.NewLocalReader(n.dm), inprocCoordinatorTimeout)
	return coordinator.NewCoordinatorHandler(
		nodeID,
		n.wc,
		readCoord,
		n.clock,
		n.dm,
		coordinator.NewDDLLockManager(time.Minute),
		db.NewSchemaVersionManager(n.dm),
		nil, // no gRPC node registry in-process
	)
}

// scalarOnNode reads a single value from one node's local database.
func scalarOnNode(t *testing.T, node *inprocNode, database, query string, args ...any) any {
	t.Helper()
	conn, err := node.dm.GetDatabaseReadConnection(database)
	require.NoError(t, err)
	var v any
	require.NoError(t, conn.QueryRow(query, args...).Scan(&v))
	return v
}

// TestTTLSweep_DeletesReplicateAcrossEveryNode drives the actual client write
// path: a TTL-marked table is created and populated on node 1, then node 1's
// TTL sweeper deletes the expired rows through the same HandleQuery path a
// client DELETE uses. With no anti-entropy or gRPC in this harness, all three
// nodes can only agree if the deletes were ordinary replicated transactions.
func TestTTLSweep_DeletesReplicateAcrossEveryNode(t *testing.T) {
	prev := cfg.Config.Replication.DefaultWriteConsist
	cfg.Config.Replication.DefaultWriteConsist = "ALL"
	t.Cleanup(func() { cfg.Config.Replication.DefaultWriteConsist = prev })

	c := newInprocCluster(t, []uint64{1, 2, 3})
	const database, table = "ttldb", "sessions"
	for _, nodeID := range []uint64{1, 2, 3} {
		require.NoError(t, c.nodes[nodeID].dm.CreateDatabase(database))
	}

	h1 := c.coordinatorHandler(t, 1)
	session := &protocol.ConnectionSession{
		CurrentDatabase:      database,
		TranspilationEnabled: true,
	}

	// CREATE carries the expiry-column directive in the MySQL table COMMENT.
	_, err := h1.HandleQuery(session,
		"CREATE TABLE sessions ("+
			"id INTEGER PRIMARY KEY, expires_at INTEGER"+
			") COMMENT='marmot:ttl=expires_at'", nil)
	require.NoError(t, err)

	// The DDL text - with the replicated marker - must land on every node.
	for _, nodeID := range []uint64{1, 2, 3} {
		n := c.nodes[nodeID]
		waitFor(t, fmt.Sprintf("node %d TTL policy", nodeID), replicationDeadline, func() (bool, string) {
			got := scalarOnNode(t, n, database,
				`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=? AND instr(sql, '/*M:TTL:') > 0`,
				table)
			n, _ := got.(int64)
			return n == 1, fmt.Sprintf("count=%v", got)
		})
	}

	now := time.Now().UTC()
	past1 := now.Add(-time.Hour).Unix()
	past2 := now.Add(-time.Minute).Unix()
	future := now.Add(time.Hour).Unix()
	past3 := now.Add(-2 * time.Hour).Unix()

	_, err = h1.HandleQuery(session,
		"INSERT INTO sessions (id, expires_at) VALUES (1, ?), (2, ?), (3, ?), (4, NULL), (5, ?)",
		[]any{past1, past2, future, past3})
	require.NoError(t, err)

	for _, nodeID := range []uint64{1, 2, 3} {
		n := c.nodes[nodeID]
		waitFor(t, fmt.Sprintf("node %d initial rows", nodeID), replicationDeadline, func() (bool, string) {
			got := scalarOnNode(t, n, database, `SELECT count(*) FROM sessions`)
			n, _ := got.(int64)
			return n == 5, fmt.Sprintf("count=%v", got)
		})
	}

	sweeper := ttl.NewSweeper(
		ttl.Config{
			Interval:   time.Hour, // driven by SweepOnce, not the ticker
			BatchSize:  2,
			BatchPause: time.Millisecond,
			Now:        func() time.Time { return now },
		},
		1,
		c.nodes[1].dm,
		h1,
		&inprocMembership{c: c, local: 1},
	)

	stat := sweeper.SweepOnce(context.Background())
	require.True(t, stat.Ran, "sweep should run on the lowest alive node: %s", stat.Reason)
	require.EqualValues(t, 3, stat.Deleted, "the three past-expiry rows are deleted")

	// Every node - including the two that only ever saw this data through
	// replication - must end with exactly the fresh and NULL rows, same ids.
	for _, nodeID := range []uint64{1, 2, 3} {
		n := c.nodes[nodeID]
		waitFor(t, fmt.Sprintf("node %d expiry convergence", nodeID), replicationDeadline, func() (bool, string) {
			count := scalarOnNode(t, n, database, `SELECT count(*) FROM sessions`)
			ids := scalarOnNode(t, n, database, `SELECT group_concat(id) FROM sessions ORDER BY id`)
			cnt, _ := count.(int64)
			return cnt == 2 && ids == "3,4", fmt.Sprintf("count=%v ids=%v", count, ids)
		})
	}
}

// TestTTLSweep_NonOwnerDeletesNothing pins ownership election: node 2 with a
// lower alive peer must not sweep, even when expired rows exist locally.
func TestTTLSweep_NonOwnerDeletesNothing(t *testing.T) {
	prev := cfg.Config.Replication.DefaultWriteConsist
	cfg.Config.Replication.DefaultWriteConsist = "ALL"
	t.Cleanup(func() { cfg.Config.Replication.DefaultWriteConsist = prev })

	c := newInprocCluster(t, []uint64{1, 2, 3})
	const database, table = "ttldb2", "sessions"
	for _, nodeID := range []uint64{1, 2, 3} {
		require.NoError(t, c.nodes[nodeID].dm.CreateDatabase(database))
	}

	h2 := c.coordinatorHandler(t, 2)
	session := &protocol.ConnectionSession{CurrentDatabase: database, TranspilationEnabled: true}
	_, err := h2.HandleQuery(session,
		"CREATE TABLE sessions (id INTEGER PRIMARY KEY, expires_at INTEGER) COMMENT='marmot:ttl=expires_at'", nil)
	require.NoError(t, err)
	for _, nodeID := range []uint64{1, 2, 3} {
		n := c.nodes[nodeID]
		waitFor(t, fmt.Sprintf("node %d policy", nodeID), replicationDeadline, func() (bool, string) {
			got := scalarOnNode(t, n, database,
				`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=? AND instr(sql, '/*M:TTL:') > 0`, table)
			v, _ := got.(int64)
			return v == 1, fmt.Sprintf("count=%v", got)
		})
	}

	now := time.Now().UTC()
	_, err = h2.HandleQuery(session,
		"INSERT INTO sessions (id, expires_at) VALUES (1, ?), (2, ?)",
		[]any{now.Add(-time.Hour).Unix(), now.Add(-time.Minute).Unix()})
	require.NoError(t, err)
	for _, nodeID := range []uint64{1, 2, 3} {
		n := c.nodes[nodeID]
		waitFor(t, fmt.Sprintf("node %d rows", nodeID), replicationDeadline, func() (bool, string) {
			got := scalarOnNode(t, n, database, `SELECT count(*) FROM sessions`)
			v, _ := got.(int64)
			return v == 2, fmt.Sprintf("count=%v", got)
		})
	}

	sweeper := ttl.NewSweeper(
		ttl.Config{
			Interval:  time.Hour,
			BatchSize: 10,
			Now:       func() time.Time { return now },
		},
		2,
		c.nodes[2].dm,
		h2,
		&inprocMembership{c: c, local: 2},
	)
	stat := sweeper.SweepOnce(context.Background())
	require.False(t, stat.Ran, "node 1 owns the round; node 2 must not delete: %s", stat.Reason)

	// Nothing was deleted anywhere.
	for _, nodeID := range []uint64{1, 2, 3} {
		got := scalarOnNode(t, c.nodes[nodeID], database, `SELECT count(*) FROM sessions`)
		v, _ := got.(int64)
		require.EqualValues(t, 2, v, "node %d rows changed without an owner sweep", nodeID)
	}
}
