package grpc

import (
	"context"
	"errors"
	"strings"

	"github.com/maxpert/marmot/db"
	"github.com/maxpert/marmot/encoding"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetTableDigests serves one database's per-table content digests for the
// cluster-wide consistency check. It only reads committed local rows; it
// never blocks replication or snapshots a consistent point across nodes,
// so a check during writes can surface transient differences.
func (s *Server) GetTableDigests(ctx context.Context, req *ConsistencyDigestRequest) (*ConsistencyDigestResponse, error) {
	mdb, err := s.consistencyDatabase(req.GetDatabase())
	if err != nil {
		return nil, err
	}

	digests, err := mdb.ConsistencyDigests(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "compute table digests: %v", err)
	}

	resp := &ConsistencyDigestResponse{Tables: make([]*ConsistencyTableDigest, 0, len(digests))}
	for i := range digests {
		d := &digests[i]
		resp.Tables = append(resp.Tables, &ConsistencyTableDigest{
			Table:             d.Table,
			PrimaryKeyColumns: d.PrimaryKey,
			Columns:           consistencyColumnsToProto(d.Columns),
			RowCount:          uint64(d.RowCount),
			Hash:              d.Hash,
			WithoutRowid:      d.WithoutRowID,
		})
	}
	return resp, nil
}

// GetRowHashes serves one page of (primary key, row hash) pairs for a
// table whose digest disagreed between nodes.
func (s *Server) GetRowHashes(ctx context.Context, req *ConsistencyRowHashRequest) (*ConsistencyRowHashResponse, error) {
	mdb, err := s.consistencyDatabase(req.GetDatabase())
	if err != nil {
		return nil, err
	}

	var after []interface{}
	if len(req.GetAfterKey()) > 0 {
		if err := encoding.UnmarshalStrict(req.GetAfterKey(), &after); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "decode after_key: %v", err)
		}
	}

	rows, nextAfter, hasMore, err := mdb.ConsistencyRowHashes(ctx, req.GetTable(), after, int(req.GetLimit()))
	if err != nil {
		return nil, consistencyQueryError(err)
	}

	resp := &ConsistencyRowHashResponse{
		Rows:    make([]*ConsistencyRowHash, 0, len(rows)),
		HasMore: hasMore,
	}
	for i := range rows {
		keyBytes, err := encoding.Marshal(rows[i].Key)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "encode row key: %v", err)
		}
		resp.Rows = append(resp.Rows, &ConsistencyRowHash{
			Key:     keyBytes,
			KeyText: db.ConsistencyRenderKey(rows[i].Key),
			Hash:    rows[i].Hash,
		})
	}
	if hasMore && len(nextAfter) > 0 {
		nextBytes, err := encoding.Marshal(nextAfter)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "encode next key: %v", err)
		}
		resp.NextAfterKey = nextBytes
	}
	return resp, nil
}

// GetRowData serves the rendered cell values of the requested keys, so a
// mismatch report can show what each node actually holds for the records
// that disagree.
func (s *Server) GetRowData(ctx context.Context, req *ConsistencyRowDataRequest) (*ConsistencyRowDataResponse, error) {
	mdb, err := s.consistencyDatabase(req.GetDatabase())
	if err != nil {
		return nil, err
	}
	if len(req.GetKeys()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "keys is required")
	}

	keys := make([][]interface{}, len(req.GetKeys()))
	for i, raw := range req.GetKeys() {
		var key []interface{}
		if err := encoding.UnmarshalStrict(raw, &key); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "decode key %d: %v", i, err)
		}
		keys[i] = key
	}

	rows, err := mdb.ConsistencyRowsByKeys(ctx, req.GetTable(), keys)
	if err != nil {
		return nil, consistencyQueryError(err)
	}

	resp := &ConsistencyRowDataResponse{Rows: make([]*ConsistencyRowData, 0, len(rows))}
	for i, row := range rows {
		entry := &ConsistencyRowData{
			Key:     req.GetKeys()[i], // echo the exact bytes the client sent
			Present: row.Present,
			Values:  make(map[string]string, len(row.Values)),
		}
		for _, v := range row.Values {
			entry.Values[v.Name] = v.Value
		}
		resp.Rows = append(resp.Rows, entry)
	}
	return resp, nil
}

// consistencyDatabase resolves the request's database with the same
// presence semantics ListCommittedLog uses: a database this node does not
// have is NotFound (the coordinator reports the node as missing the whole
// database), a detached one is Unavailable, and an unwired server is
// Unavailable.
func (s *Server) consistencyDatabase(name string) (*db.ReplicatedDatabase, error) {
	s.mu.RLock()
	dbManager := s.dbManager
	s.mu.RUnlock()
	if dbManager == nil {
		return nil, status.Error(codes.Unavailable, "database manager not initialized")
	}
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "database is required")
	}
	mdb, err := dbManager.GetDatabase(name)
	if err != nil {
		if errors.Is(err, db.ErrDatabaseDetached) {
			return nil, status.Errorf(codes.Unavailable, "database %s: %v", name, err)
		}
		return nil, status.Errorf(codes.NotFound, "database %s not found on this node", name)
	}
	return mdb, nil
}

// consistencyQueryError maps a local query failure to a gRPC status: an
// unknown table is the caller asking about a table absent from this node
// (digest comparison already names a missing table separately), everything
// else is an internal failure.
func consistencyQueryError(err error) error {
	msg := err.Error()
	// The exact phrases consistencyTableMeta and SQLite use for an unknown
	// table; kept narrow on purpose.
	if strings.Contains(msg, "does not exist") || strings.Contains(msg, "no such table") {
		return status.Errorf(codes.NotFound, "%v", err)
	}
	return status.Errorf(codes.Internal, "%v", err)
}

func consistencyColumnsToProto(cols []db.ConsistencyColumn) []*ConsistencyColumn {
	out := make([]*ConsistencyColumn, 0, len(cols))
	for _, c := range cols {
		out = append(out, &ConsistencyColumn{Name: c.Name, Type: c.Type})
	}
	return out
}
