package grpc

import (
	"context"
	"testing"

	"github.com/maxpert/marmot/db"
	"github.com/maxpert/marmot/encoding"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// twoConsistencyNodes spins up two in-process nodes serving real gRPC, each
// with an "app" database (table t(id INTEGER PRIMARY KEY, v TEXT)), and
// returns a client on node 1 connected to node 2.
func twoConsistencyNodes(t *testing.T, rows ...string) (*aeRegNode, *aeRegNode, MarmotServiceClient) {
	t.Helper()
	n1 := newAERegNode(t, 1, "app")
	n2 := newAERegNode(t, 2, "app")
	n1.serve(t)
	n2.serve(t)

	insert := func(n *aeRegNode) {
		mdb, err := n.dm.GetDatabase("app")
		require.NoError(t, err)
		for i, v := range rows {
			_, err := mdb.GetWriteDB().Exec(`INSERT INTO t (id, v) VALUES (?, ?)`, i+1, v)
			require.NoError(t, err)
		}
	}
	insert(n1)
	insert(n2)

	require.NoError(t, n1.client.Connect(n2.id, n2.addr))
	cli, err := n1.client.GetClient(n2.id)
	require.NoError(t, err)
	return n1, n2, cli
}

func localDigest(t *testing.T, ctx context.Context, n *aeRegNode, table string) *db.ConsistencyTableDigest {
	t.Helper()
	mdb, err := n.dm.GetDatabase("app")
	require.NoError(t, err)
	digests, err := mdb.ConsistencyDigests(ctx)
	require.NoError(t, err)
	for i := range digests {
		if digests[i].Table == table {
			return &digests[i]
		}
	}
	t.Fatalf("table %s not in local digests", table)
	return nil
}

// TestConsistencyRPCDigests: identical nodes report identical digests over
// the wire; a row changed on the peer flips that table's digest.
func TestConsistencyRPCDigests(t *testing.T) {
	ctx := context.Background()
	n1, n2, cli := twoConsistencyNodes(t, "alice", "bob", "carol")

	resp, err := cli.GetTableDigests(ctx, &ConsistencyDigestRequest{RequestingNodeId: n1.id, Database: "app"})
	require.NoError(t, err)
	require.Len(t, resp.GetTables(), 1)
	remote := resp.GetTables()[0]
	require.Equal(t, "t", remote.GetTable())
	require.Equal(t, []string{"id"}, remote.GetPrimaryKeyColumns())

	local := localDigest(t, ctx, n1, "t")
	require.Equal(t, uint64(local.RowCount), remote.GetRowCount())
	require.Equal(t, local.Hash, remote.GetHash())
	require.Equal(t, db.ConsistencyColumnSignature(local.Columns),
		consistencySignatureFromProto(remote.GetColumns()))

	// Diverge one row on node 2: its digest moves, node 1's stays.
	mdb2, err := n2.dm.GetDatabase("app")
	require.NoError(t, err)
	_, err = mdb2.GetWriteDB().Exec(`UPDATE t SET v = 'BOB' WHERE id = 2`)
	require.NoError(t, err)

	resp, err = cli.GetTableDigests(ctx, &ConsistencyDigestRequest{Database: "app"})
	require.NoError(t, err)
	require.NotEqual(t, local.Hash, resp.GetTables()[0].GetHash())
}

// TestConsistencyRPCRowHashesPagesAndLocatesRow: paging works over gRPC,
// key bytes decode back to the primary key tuple, and the changed row is
// the only one whose hash differs - exactly the evidence the coordinator
// uses to name a record.
func TestConsistencyRPCRowHashesPagesAndLocatesRow(t *testing.T) {
	ctx := context.Background()
	n1, n2, cli := twoConsistencyNodes(t, "alice", "bob", "carol")

	collect := func(c MarmotServiceClient) (map[string]uint64, []string) {
		t.Helper()
		byKey := map[string]uint64{}
		var order []string
		var after []byte
		for {
			resp, err := c.GetRowHashes(ctx, &ConsistencyRowHashRequest{
				Database: "app", Table: "t", AfterKey: after, Limit: 2,
			})
			require.NoError(t, err)
			for _, r := range resp.GetRows() {
				var key []interface{}
				require.NoError(t, encoding.UnmarshalStrict(r.GetKey(), &key))
				require.Equal(t, []interface{}{int64(len(order) + 1)}, key, "keys arrive in id order")
				byKey[r.GetKeyText()] = r.GetHash()
				order = append(order, r.GetKeyText())
			}
			if !resp.GetHasMore() {
				break
			}
			after = resp.GetNextAfterKey()
			require.NotEmpty(t, after)
		}
		return byKey, order
	}

	before1, order1 := collect(cli)
	require.Equal(t, []string{"i:1", "i:2", "i:3"}, order1)

	// Same data on node 1 locally: identical per-row hashes.
	mdb1, err := n1.dm.GetDatabase("app")
	require.NoError(t, err)
	localRows, _, _, err := mdb1.ConsistencyRowHashes(ctx, "t", nil, 10)
	require.NoError(t, err)
	for _, r := range localRows {
		raw, err := encoding.Marshal(r.Key)
		require.NoError(t, err)
		var tuple []interface{}
		require.NoError(t, encoding.UnmarshalStrict(raw, &tuple))
		require.Equal(t, r.Hash, before1[db.ConsistencyRenderKey(tuple)])
	}

	// Change id=2 on node 2: only i:2 flips.
	mdb2, err := n2.dm.GetDatabase("app")
	require.NoError(t, err)
	_, err = mdb2.GetWriteDB().Exec(`UPDATE t SET v = 'BOB' WHERE id = 2`)
	require.NoError(t, err)
	after2, _ := collect(cli)
	require.Equal(t, before1["i:1"], after2["i:1"])
	require.Equal(t, before1["i:3"], after2["i:3"])
	require.NotEqual(t, before1["i:2"], after2["i:2"])

	// Fetch the divergent row's values from both nodes: reports the truth.
	values2, err := cli.GetRowData(ctx, &ConsistencyRowDataRequest{
		Database: "app", Table: "t", Keys: [][]byte{mustMarshalKey(t, int64(2)), mustMarshalKey(t, int64(99))},
	})
	require.NoError(t, err)
	require.Len(t, values2.GetRows(), 2)
	require.True(t, values2.GetRows()[0].GetPresent())
	require.Equal(t, "s:BOB", values2.GetRows()[0].GetValues()["v"])
	require.False(t, values2.GetRows()[1].GetPresent())
}

// TestConsistencyRPCErrors maps local absence to wire status codes the
// coordinator relies on.
func TestConsistencyRPCErrors(t *testing.T) {
	ctx := context.Background()
	_, _, cli := twoConsistencyNodes(t, "alice")

	_, err := cli.GetTableDigests(ctx, &ConsistencyDigestRequest{Database: "ghost"})
	require.Equal(t, codes.NotFound, status.Code(err))

	_, err = cli.GetTableDigests(ctx, &ConsistencyDigestRequest{Database: ""})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = cli.GetRowHashes(ctx, &ConsistencyRowHashRequest{Database: "app", Table: "t", AfterKey: []byte("not-msgpack")})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = cli.GetRowHashes(ctx, &ConsistencyRowHashRequest{Database: "app", Table: "ghost"})
	require.Equal(t, codes.NotFound, status.Code(err))

	_, err = cli.GetRowData(ctx, &ConsistencyRowDataRequest{Database: "app", Table: "t"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func mustMarshalKey(t *testing.T, key ...interface{}) []byte {
	t.Helper()
	raw, err := encoding.Marshal(key)
	require.NoError(t, err)
	return raw
}

func consistencySignatureFromProto(cols []*ConsistencyColumn) string {
	out := make([]db.ConsistencyColumn, 0, len(cols))
	for _, c := range cols {
		out = append(out, db.ConsistencyColumn{Name: c.GetName(), Type: c.GetType()})
	}
	return db.ConsistencyColumnSignature(out)
}
