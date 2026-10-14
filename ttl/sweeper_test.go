package ttl

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/maxpert/marmot/db"
	"github.com/maxpert/marmot/protocol"
	"github.com/stretchr/testify/require"
)

// fakeExec executes sweep statements against the same real SQLite database the
// read side scans. In production the statement instead goes through 2PC and
// CDC; the in-process cluster test covers that half.
type fakeExec struct {
	db     *sql.DB
	mu     sync.Mutex
	calls  int
	drain  bool
	failOn int // 1-based call to fail (simulates a row-lock conflict), 0 = never
}

func (f *fakeExec) HandleQuery(_ *protocol.ConnectionSession, query string, params []interface{}) (*protocol.ResultSet, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	drain := f.drain
	fail := f.failOn == call
	f.mu.Unlock()

	if drain {
		return nil, fmt.Errorf("server is draining")
	}
	if fail {
		return nil, fmt.Errorf("could not acquire row lock (1205)")
	}
	res, err := f.db.Exec(query, params...)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	return &protocol.ResultSet{RowsAffected: n}, nil
}

func (f *fakeExec) IsDraining() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.drain
}

type fakeLister struct {
	dbs map[string]*sql.DB
}

func (l *fakeLister) ListDatabases() []string {
	names := make([]string, 0, len(l.dbs))
	for name := range l.dbs {
		names = append(names, name)
	}
	return names
}

func (l *fakeLister) GetDatabaseReadConnection(name string) (*sql.DB, error) {
	if conn, ok := l.dbs[name]; ok {
		return conn, nil
	}
	return nil, fmt.Errorf("no database %q", name)
}

type fakeMembers struct {
	local uint64
	alive []uint64
}

func (m *fakeMembers) LocalNodeID() uint64   { return m.local }
func (m *fakeMembers) AliveNodeIDs() []uint64 { return append([]uint64(nil), m.alive...) }

func newSweepDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sweep.db")
	conn, err := sql.Open(db.SQLiteDriverName, path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn, path
}

func TestSweepOnce_DeletesExpiredKeepsFreshAndNull(t *testing.T) {
	conn, _ := newSweepDB(t)
	_, err := conn.Exec(`CREATE TABLE sessions (
		id INTEGER PRIMARY KEY,
		expires_at INTEGER
	 /*M:TTL:expires_at*/)`)
	require.NoError(t, err)

	now := time.Now().UTC()
	_, err = conn.Exec(`INSERT INTO sessions (id, expires_at) VALUES
		(1, ?), (2, ?), (3, ?), (4, NULL), (5, ?)`,
		now.Add(-time.Hour).Unix(),
		now.Add(-time.Second).Unix(),
		now.Add(time.Hour).Unix(),
		now.Add(time.Minute).Unix())
	require.NoError(t, err)

	exec := &fakeExec{db: conn}
	s := NewSweeper(Config{
		Interval:   time.Minute,
		BatchSize:  2, // forces several bounded batches
		BatchPause: time.Millisecond,
		Now:         func() time.Time { return now },
	}, 2, &fakeLister{dbs: map[string]*sql.DB{"app": conn}}, exec, &fakeMembers{local: 2, alive: []uint64{2, 3}})

	stat := s.SweepOnce(context.Background())
	require.True(t, stat.Ran, "round should run: %s", stat.Reason)
	require.EqualValues(t, 2, stat.Deleted)
	require.GreaterOrEqual(t, exec.calls, 2, "5-row table should need more than one size-2 batch")

	var count int
	require.NoError(t, conn.QueryRow(`SELECT count(*) FROM sessions`).Scan(&count))
	require.Equal(t, 3, count, "fresh and NULL rows must remain")

	var ids string
	require.NoError(t, conn.QueryRow(`SELECT group_concat(id) FROM sessions ORDER BY id`).Scan(&ids))
	require.Equal(t, "3,4,5", ids)
}

func TestSweepOnce_TextExpiryColumn(t *testing.T) {
	conn, _ := newSweepDB(t)
	_, err := conn.Exec(`CREATE TABLE events (
		rowid_alias INTEGER PRIMARY KEY,
		expires_at TEXT
	 /*M:TTL:expires_at*/)`)
	require.NoError(t, err)

	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	_, err = conn.Exec(`INSERT INTO events (rowid_alias, expires_at) VALUES
		(1, '2026-03-04 11:59:59'), (2, '2026-03-04 12:00:01'), (3, NULL)`)
	require.NoError(t, err)

	exec := &fakeExec{db: conn}
	s := NewSweeper(Config{BatchSize: 100, Now: func() time.Time { return now }},
		1, &fakeLister{dbs: map[string]*sql.DB{"app": conn}}, exec, nil)

	stat := s.SweepOnce(context.Background())
	require.EqualValues(t, 1, stat.Deleted, "%+v", stat)
}

func TestSweepOnce_NotOwnerSkips(t *testing.T) {
	conn, _ := newSweepDB(t)
	_, err := conn.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, expires_at INTEGER /*M:TTL:expires_at*/)`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO t VALUES (1, 1)`)
	require.NoError(t, err)

	exec := &fakeExec{db: conn}
	members := &fakeMembers{local: 2, alive: []uint64{1, 2, 3}} // node 1 owns
	s := NewSweeper(Config{BatchSize: 10}, 2,
		&fakeLister{dbs: map[string]*sql.DB{"app": conn}}, exec, members)

	stat := s.SweepOnce(context.Background())
	require.False(t, stat.Ran)
	require.Equal(t, "not the sweep owner", stat.Reason)
	require.Equal(t, 0, exec.calls)
}

func TestSweepOnce_OwnerWhenLowestAlive(t *testing.T) {
	conn, _ := newSweepDB(t)
	_, err := conn.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, expires_at INTEGER /*M:TTL:expires_at*/)`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO t VALUES (1, 1)`)
	require.NoError(t, err)

	for _, local := range []uint64{1, 2, 3} {
		exec := &fakeExec{db: conn}
		// Every node sees the same alive set; only the lowest id may delete.
		members := &fakeMembers{local: local, alive: []uint64{1, 2, 3}}
		s := NewSweeper(Config{BatchSize: 10}, local,
			&fakeLister{dbs: map[string]*sql.DB{"app": conn}}, exec, members)
		stat := s.SweepOnce(context.Background())
		require.Equal(t, local == 1, stat.Ran, "node %d Ran=%v (%s)", local, stat.Ran, stat.Reason)
	}
}

func TestSweepOnce_NotAliveSkips(t *testing.T) {
	conn, _ := newSweepDB(t)
	exec := &fakeExec{db: conn}
	// A JOINING node is not in the ALIVE set, not even in its own view.
	members := &fakeMembers{local: 2, alive: nil}
	s := NewSweeper(Config{BatchSize: 10}, 2,
		&fakeLister{dbs: map[string]*sql.DB{"app": conn}}, exec, members)
	stat := s.SweepOnce(context.Background())
	require.False(t, stat.Ran)
	require.Equal(t, 0, exec.calls)
}

func TestSweepOnce_DrainingSkips(t *testing.T) {
	conn, _ := newSweepDB(t)
	exec := &fakeExec{db: conn, drain: true}
	s := NewSweeper(Config{BatchSize: 10}, 1,
		&fakeLister{dbs: map[string]*sql.DB{"app": conn}}, exec, nil)
	stat := s.SweepOnce(context.Background())
	require.False(t, stat.Ran)
	require.Equal(t, "node is draining", stat.Reason)
}

func TestSweepOnce_ContextCanceledBeforeRound(t *testing.T) {
	conn, _ := newSweepDB(t)
	s := NewSweeper(Config{BatchSize: 10}, 1,
		&fakeLister{dbs: map[string]*sql.DB{"app": conn}}, &fakeExec{db: conn}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stat := s.SweepOnce(ctx)
	require.True(t, stat.Ran) // ownership passed; rounds stop once a database is touched
	require.EqualValues(t, 0, stat.Deleted)
}

func TestSweepOnce_WithoutRowidSkipped(t *testing.T) {
	conn, _ := newSweepDB(t)
	_, err := conn.Exec(`CREATE TABLE kv (
		k TEXT PRIMARY KEY, expires_at INTEGER
 /*M:TTL:expires_at*/) WITHOUT ROWID`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO kv VALUES ('a', 1)`)
	require.NoError(t, err)

	exec := &fakeExec{db: conn}
	s := NewSweeper(Config{BatchSize: 10}, 1,
		&fakeLister{dbs: map[string]*sql.DB{"app": conn}}, exec, nil)
	stat := s.SweepOnce(context.Background())
	require.Len(t, stat.Tables, 1)
	require.NotEmpty(t, stat.Tables[0].SkipReason)
	require.Equal(t, 0, exec.calls)
}

func TestSweepOnce_MissingExpiryColumnSkipped(t *testing.T) {
	conn, _ := newSweepDB(t)
	// Marker names a column the table does not declare.
	_, err := conn.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY /*M:TTL:expires_at*/)`)
	require.NoError(t, err)

	s := NewSweeper(Config{BatchSize: 10}, 1,
		&fakeLister{dbs: map[string]*sql.DB{"app": conn}}, &fakeExec{db: conn}, nil)
	stat := s.SweepOnce(context.Background())
	require.Len(t, stat.Tables, 1)
	require.Contains(t, stat.Tables[0].SkipReason, "no longer exists")
}

func TestSweepOnce_UnsupportedColumnTypeSkipped(t *testing.T) {
	conn, _ := newSweepDB(t)
	_, err := conn.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, expires_at BLOB /*M:TTL:expires_at*/)`)
	require.NoError(t, err)

	s := NewSweeper(Config{BatchSize: 10}, 1,
		&fakeLister{dbs: map[string]*sql.DB{"app": conn}}, &fakeExec{db: conn}, nil)
	stat := s.SweepOnce(context.Background())
	require.Len(t, stat.Tables, 1)
	require.Contains(t, stat.Tables[0].SkipReason, "unsupported type")
}

func TestSweepOnce_NoPolicyNoWrites(t *testing.T) {
	conn, _ := newSweepDB(t)
	_, err := conn.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, expires_at INTEGER)`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO t VALUES (1, 1)`)
	require.NoError(t, err)

	exec := &fakeExec{db: conn}
	s := NewSweeper(Config{BatchSize: 10}, 1,
		&fakeLister{dbs: map[string]*sql.DB{"app": conn}}, exec, nil)
	stat := s.SweepOnce(context.Background())
	require.True(t, stat.Ran)
	require.Empty(t, stat.Tables)
	require.Equal(t, 0, exec.calls)
}

func TestSweepOnce_SystemDatabaseExcluded(t *testing.T) {
	systemConn, _ := newSweepDB(t)
	_, err := systemConn.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, expires_at INTEGER /*M:TTL:expires_at*/)`)
	require.NoError(t, err)
	_, err = systemConn.Exec(`INSERT INTO t VALUES (1, 1)`)
	require.NoError(t, err)

	exec := &fakeExec{db: systemConn}
	s := NewSweeper(Config{BatchSize: 10}, 1,
		&fakeLister{dbs: map[string]*sql.DB{systemDatabaseName: systemConn}}, exec, nil)
	stat := s.SweepOnce(context.Background())
	require.Empty(t, stat.Tables)
	require.Equal(t, 0, exec.calls)
}

func TestSweepOnce_LockConflictAbortsTableAndNextRoundRetries(t *testing.T) {
	conn, _ := newSweepDB(t)
	_, err := conn.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, expires_at INTEGER /*M:TTL:expires_at*/)`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO t VALUES (1, 1)`)
	require.NoError(t, err)

	exec := &fakeExec{db: conn, failOn: 1}
	s := NewSweeper(Config{BatchSize: 10}, 1,
		&fakeLister{dbs: map[string]*sql.DB{"app": conn}}, exec, nil)
	stat := s.SweepOnce(context.Background())
	require.EqualValues(t, 0, stat.Deleted, "failed first batch deletes nothing")
	var n int
	require.NoError(t, conn.QueryRow(`SELECT count(*) FROM t`).Scan(&n))
	require.Equal(t, 1, n)

	// Next round is a fresh attempt and succeeds.
	exec.failOn = 0
	stat = s.SweepOnce(context.Background())
	require.EqualValues(t, 1, stat.Deleted)
}
