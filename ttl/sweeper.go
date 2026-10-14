// Package ttl implements background row-expiry cleanup (data time-to-live).
//
// A table opts in with a COMMENT directive at CREATE TABLE:
//
//	CREATE TABLE sessions (
//	  id INTEGER PRIMARY KEY,
//	  expires_at INTEGER NOT NULL
//	) COMMENT='marmot:ttl=expires_at';
//
// The directive rides the replicated DDL text as the /*M:TTL:column*/ marker,
// placed just before the CREATE's closing parenthesis (SQLite drops comments
// after a statement's final token). See protocol/query/transform/ttlmarker;
// every node derives the same policies from its own sqlite_master.
//
// Two requirements shape the implementation:
//
//   - Cleanup must not disturb normal writes. Each sweep is a sequence of
//     ordinary autocommit transactions bounded by BatchSize, with a pause
//     between batches. Cleanup never takes a DDL lock or a long SQLite writer
//     transaction, and it stops while the node is draining for shutdown.
//   - Every node has to end with the same rows. Exactly one ALIVE member per
//     round - the lowest-numbered one - issues deletes, and those deletes go
//     through the same HandleQuery write path as a client DELETE, so 2PC,
//     CDC replication and per-row LWW tombstones propagate them to every node.
//     Ownership is advisory and stateless: if the owner leaves mid-sweep, the
//     next owner simply repeats bounded, idempotent deletes. A node that was
//     down catches the deletes up through anti-entropy.
package ttl

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/maxpert/marmot/protocol"
	"github.com/maxpert/marmot/protocol/query/transform/ttlmarker"
	"github.com/rs/zerolog/log"
)

// systemDatabaseName mirrors db.SystemDatabaseName /
// coordinator.SystemDatabaseName. The system database is per-node state and is
// never given a TTL policy.
const systemDatabaseName = "__marmot_system"

// markerLit is the SQL literal the sqlite_master scan looks for. It is fixed
// DDL text, not user input, so inlining it needs no escaping.
const markerLit = "/*M:TTL:"

// expiryTextLayout is how TEXT expiry columns hold absolute expiry time, in
// UTC. Comparison is lexicographic, which is correct for this fixed-width
// layout.
const expiryTextLayout = "2006-01-02 15:04:05"

// DatabaseLister lists the attached user databases and offers their read
// pools. *db.DatabaseManager satisfies it.
type DatabaseLister interface {
	ListDatabases() []string
	GetDatabaseReadConnection(name string) (*sql.DB, error)
}

// Executor runs an autocommit statement through the cluster's normal write
// path, so the work replicates like any client write. The coordinator's
// *coordinator.CoordinatorHandler satisfies it.
type Executor interface {
	HandleQuery(session *protocol.ConnectionSession, sqlText string, params []interface{}) (*protocol.ResultSet, error)
	// IsDraining reports whether the node is rejecting new writes (graceful
	// shutdown); a round must not start while it is.
	IsDraining() bool
}

// Membership is the cluster membership view ownership election uses.
// marmot.go adapts *marmotgrpc.NodeRegistry to it.
type Membership interface {
	LocalNodeID() uint64
	// AliveNodeIDs returns every ALIVE member, self included.
	AliveNodeIDs() []uint64
}

// Config controls the sweeper.
type Config struct {
	// Interval bounds how far apart sweep rounds start.
	Interval time.Duration
	// BatchSize is the most rows one sweep transaction deletes.
	BatchSize int
	// BatchPause is yielded between two batches of the same table so the
	// single SQLite writer stays available to client writes.
	BatchPause time.Duration
	// Now is the wall clock expiry is measured against (default time.Now).
	Now func() time.Time
}

// TableStat reports one table's sweep outcome.
type TableStat struct {
	Database     string
	Table        string
	ExpiryColumn string
	Deleted      int64
	// SkipReason is non-empty when the table carried a policy but was not
	// swept this round (unsupported shape, unreadable schema, ...).
	SkipReason string
}

// RoundStat reports one sweep round.
type RoundStat struct {
	// Ran is false when the round was skipped, with Reason saying why.
	Ran bool
	// Reason reports why a round did not run or stopped early.
	Reason string
	// Owner is the node id that owned the round, this node when Ran.
	Owner uint64

	Tables []TableStat
	// Deleted is the round's total deleted rows.
	Deleted int64
}

// Sweeper periodically deletes rows whose expiry column is in the past.
type Sweeper struct {
	cfg     Config
	nodeID  uint64
	dbs     DatabaseLister
	exec    Executor
	members Membership

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	runMu sync.Mutex
}

// NewSweeper builds a sweeper. members may be nil for single-node embedders;
// such a sweeper always owns the round.
func NewSweeper(cfg Config, nodeID uint64, dbs DatabaseLister, exec Executor, members Membership) *Sweeper {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	return &Sweeper{
		cfg:     cfg,
		nodeID:  nodeID,
		dbs:     dbs,
		exec:    exec,
		members: members,
	}
}

// Start launches the background loop. It is safe to call once; later calls
// are ignored.
func (s *Sweeper) Start(parent context.Context) {
	if parent == nil {
		parent = context.Background()
	}
	s.ctx, s.cancel = context.WithCancel(parent)
	s.wg.Add(1)
	go s.loop()
	log.Info().
		Dur("interval", s.cfg.Interval).
		Int("batch_size", s.cfg.BatchSize).
		Msg("TTL sweeper started")
}

// Stop cancels the loop and waits for the current round to finish the batch it
// is inside.
func (s *Sweeper) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func (s *Sweeper) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			stat := s.SweepOnce(s.ctx)
			if stat.Deleted > 0 {
				log.Info().
					Uint64("node_id", s.nodeID).
					Int64("rows", stat.Deleted).
					Int("tables", len(stat.Tables)).
					Msg("TTL sweep deleted expired rows")
			}
		}
	}
}

// isOwner reports whether this node must run the round: the lowest-numbered
// ALIVE member. Deterministic ownership is what keeps two nodes from deleting
// the same rows at the same time; the deletes themselves are what make every
// node converge.
func (s *Sweeper) isOwner() (uint64, bool) {
	if s.members == nil {
		return s.nodeID, true
	}
	alive := s.members.AliveNodeIDs()
	if len(alive) == 0 {
		// Not promoted yet, or between registry snapshots - do not sweep.
		return 0, false
	}
	owner := alive[0]
	for _, id := range alive[1:] {
		if id < owner {
			owner = id
		}
	}
	return owner, owner == s.nodeID
}

// SweepOnce runs exactly one sweep round across every attached database. It is
// exported for tests and admin-triggered cleanup.
func (s *Sweeper) SweepOnce(ctx context.Context) RoundStat {
	s.runMu.Lock()
	defer s.runMu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	stat := RoundStat{}

	if s.exec != nil && s.exec.IsDraining() {
		stat.Reason = "node is draining"
		return stat
	}
	owner, ok := s.isOwner()
	stat.Owner = owner
	if !ok {
		stat.Reason = "not the sweep owner"
		return stat
	}
	stat.Ran = true
	now := s.cfg.Now().UTC()

	for _, database := range s.dbs.ListDatabases() {
		if database == systemDatabaseName {
			continue
		}
		if ctx.Err() != nil {
			stat.Reason = "stopped"
			return stat
		}
		s.sweepDatabase(ctx, database, now, &stat)
	}
	return stat
}

func (s *Sweeper) sweepDatabase(ctx context.Context, database string, now time.Time, stat *RoundStat) {
	conn, err := s.dbs.GetDatabaseReadConnection(database)
	if err != nil {
		log.Warn().Err(err).Str("database", database).Msg("TTL sweep: open read connection")
		return
	}

	policies, err := discoverPolicies(conn)
	if err != nil {
		log.Warn().Err(err).Str("database", database).Msg("TTL sweep: list policies")
		return
	}
	for _, pol := range policies {
		if ctx.Err() != nil {
			stat.Reason = "stopped"
			return
		}
		tableStat := s.sweepTable(ctx, conn, database, pol, now)
		if tableStat.SkipReason != "" {
			log.Debug().
				Str("database", database).
				Str("table", pol.Table).
				Str("reason", tableStat.SkipReason).
				Msg("TTL sweep skipped table")
		}
		stat.Tables = append(stat.Tables, tableStat)
		stat.Deleted += tableStat.Deleted
	}
}

// policy is one table's TTL policy as derived from its stored DDL.
type policy struct {
	Table        string
	CreateSQL    string
	ExpiryColumn string
}

// discoverPolicies lists the tables whose stored CREATE text carries the TTL
// marker.
func discoverPolicies(conn *sql.DB) ([]policy, error) {
	rows, err := conn.Query(
		`SELECT name, sql FROM sqlite_master WHERE type = 'table' AND instr(sql, '` + markerLit + `') > 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []policy
	for rows.Next() {
		var name, createSQL string
		if err := rows.Scan(&name, &createSQL); err != nil {
			return nil, err
		}
		col, ok := ttlmarker.Decode(createSQL)
		if !ok {
			// The instr hit could have been text inside a default value; the
			// marker decoder knows how to tell them apart.
			continue
		}
		out = append(out, policy{Table: name, CreateSQL: createSQL, ExpiryColumn: col})
	}
	return out, rows.Err()
}

var withoutRowidRE = regexp.MustCompile(`(?is)without\s+rowid`)

// columnAffinity is how an expiry column is compared against now.
type columnAffinity int

const (
	affUnsupported columnAffinity = iota
	// affSeconds: integer Unix epoch seconds, compared numerically.
	affSeconds
	// affText: UTC 'YYYY-MM-DD HH:MM:SS' text, compared lexicographically.
	affText
)

func (s *Sweeper) sweepTable(ctx context.Context, conn *sql.DB, database string, pol policy, now time.Time) TableStat {
	ts := TableStat{Database: database, Table: pol.Table, ExpiryColumn: pol.ExpiryColumn}

	if withoutRowidRE.MatchString(pol.CreateSQL) {
		ts.SkipReason = "WITHOUT ROWID tables are not swept yet"
		return ts
	}

	affinity, ok, err := expiryColumnAffinity(conn, pol.Table, pol.ExpiryColumn)
	if err != nil {
		ts.SkipReason = fmt.Sprintf("read expiry column: %v", err)
		return ts
	}
	if !ok {
		ts.SkipReason = fmt.Sprintf("expiry column %q no longer exists", pol.ExpiryColumn)
		return ts
	}
	if affinity == affUnsupported {
		ts.SkipReason = fmt.Sprintf("expiry column %q has unsupported type; use INTEGER (epoch seconds) or TEXT", pol.ExpiryColumn)
		return ts
	}

	var cutoff any
	switch affinity {
	case affSeconds:
		cutoff = now.Unix()
	case affText:
		cutoff = now.Format(expiryTextLayout)
	}

	qtable := quoteIdent(pol.Table)
	qcol := quoteIdent(pol.ExpiryColumn)
	// LIMIT is an internal integer constant (never user input), so it is
	// inlined; only the cutoff is bound.
	delSQL := fmt.Sprintf(
		"DELETE FROM %s WHERE rowid IN ("+
			"SELECT rowid FROM %s WHERE %s IS NOT NULL AND %s < ? LIMIT %d)",
		qtable, qtable, qcol, qcol, s.cfg.BatchSize)

	session := &protocol.ConnectionSession{
		ConnID:               internalConnID,
		CurrentDatabase:      database,
		TranspilationEnabled: true,
	}

	for {
		if err := ctx.Err(); err != nil {
			ts.SkipReason = "stopped"
			return ts
		}
		rs, err := s.exec.HandleQuery(session, delSQL, []any{cutoff})
		if err != nil {
			// Lock conflicts are ordinary: a client write owns rows this
			// batch matched. The next round reaches the rest.
			log.Debug().Err(err).
				Str("database", database).
				Str("table", pol.Table).
				Msg("TTL sweep batch failed, will retry next round")
			return ts
		}
		n := int64(0)
		if rs != nil {
			n = rs.RowsAffected
		}
		ts.Deleted += n
		if n < int64(s.cfg.BatchSize) {
			return ts
		}
		select {
		case <-ctx.Done():
			ts.SkipReason = "stopped"
			return ts
		case <-time.After(s.cfg.BatchPause):
		}
	}
}

// expiryColumnAffinity resolves the expiry column's declared type via
// PRAGMA table_xinfo and picks its comparison rule. ok is false when the table
// has no such column.
func expiryColumnAffinity(conn *sql.DB, table, column string) (columnAffinity, bool, error) {
	query := "PRAGMA table_xinfo(" + quoteIdent(table) + ")"
	rows, err := conn.Query(query)
	if err != nil {
		return affUnsupported, false, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid, notNull, pk, hidden int
			name, typ               string
			dflt                    any
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk, &hidden); err != nil {
			return affUnsupported, false, err
		}
		if !strings.EqualFold(name, column) {
			continue
		}
		return affinityFromType(typ), true, nil
	}
	if err := rows.Err(); err != nil {
		return affUnsupported, false, err
	}
	return affUnsupported, false, nil
}

// affinityFromType mirrors SQLite's type affinity rules for the shapes an
// expiry timestamp can take: integer epoch seconds, or fixed-layout UTC text.
func affinityFromType(declared string) columnAffinity {
	upper := strings.ToUpper(declared)
	switch {
	case strings.Contains(upper, "INT"):
		return affSeconds
	case strings.Contains(upper, "TEXT"),
		strings.Contains(upper, "CHAR"),
		strings.Contains(upper, "CLOB"),
		strings.Contains(upper, "DATE"),
		strings.Contains(upper, "TIME"):
		return affText
	default:
		// BLOB, REAL, NUMERIC and typeless columns have no unambiguous
		// timestamp representation.
		return affUnsupported
	}
}

// quoteIdent renders name as a double-quoted SQLite identifier, doubling any
// embedded quote. Names here come from sqlite_master, not from a client, so
// this is defence in depth rather than user-input escaping.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// internalConnID is the synthetic connection id sweeper statements carry. It is
// outside the id space the MySQL server allocates for real connections.
const internalConnID = ^uint64(0)
