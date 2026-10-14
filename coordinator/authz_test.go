package coordinator_test

import (
	"crypto/sha1"
	"errors"
	"testing"
	"time"

	"github.com/maxpert/marmot/auth"
	"github.com/maxpert/marmot/cfg"
	"github.com/maxpert/marmot/coordinator"
	"github.com/maxpert/marmot/db"
	"github.com/maxpert/marmot/hlc"
	"github.com/maxpert/marmot/protocol"
	"github.com/maxpert/marmot/protocol/mysqlcode"
	"github.com/stretchr/testify/require"
)

func setupAuthzHandler(t *testing.T) (*coordinator.CoordinatorHandler, *auth.Manager) {
	t.Helper()
	tmpDir := t.TempDir()
	clock := hlc.NewClock(1)

	dbMgr, err := db.NewDatabaseManager(tmpDir, 1, clock)
	require.NoError(t, err)
	t.Cleanup(func() { dbMgr.Close() })
	require.NoError(t, dbMgr.MergeAutoIncBasesAndReleaseVotes(nil))

	for _, name := range []string{"appa", "appb", "shared"} {
		require.NoError(t, dbMgr.CreateDatabase(name))
	}

	h := coordinator.NewCoordinatorHandler(
		1,
		nil, // denied/metadata paths never reach the coordinators
		nil,
		clock,
		dbMgr,
		coordinator.NewDDLLockManager(30*time.Second),
		nil,
		nil,
	)
	mgr, err := auth.NewManager([]cfg.MySQLUserConfiguration{
		{Name: "appuser", Password: "app-pw", Databases: []string{"appa"}},
		{Name: "ro", Password: "ro-pw", Databases: []string{"appa", "shared"}, ReadOnly: true},
		{Name: "admin", Password: "admin-pw", Databases: []string{"*"}},
	})
	require.NoError(t, err)
	h.SetAuthManager(mgr)
	return h, mgr
}

func nativeScrambleFor(password string, salt []byte) []byte {
	stage1 := sha1.Sum([]byte(password))
	stage2 := sha1.Sum(stage1[:])
	h := sha1.New()
	h.Write(salt)
	h.Write(stage2[:])
	digest := h.Sum(nil)
	out := make([]byte, 20)
	for i := range out {
		out[i] = stage1[i] ^ digest[i]
	}
	return out
}

func authzSession(t *testing.T, mgr *auth.Manager, name, password string) *protocol.ConnectionSession {
	t.Helper()
	salt := auth.GenerateSalt()
	id, err := mgr.Authenticate(name, nativeScrambleFor(password, salt[:]), salt[:], "127.0.0.1:5000")
	require.NoError(t, err)
	return &protocol.ConnectionSession{ConnID: 1, Identity: id, TranspilationEnabled: true}
}

func requireMySQLError(t *testing.T, err error, code uint16) {
	t.Helper()
	require.Error(t, err)
	var authErr *auth.Error
	if errors.As(err, &authErr) {
		require.Equal(t, code, authErr.Code, "auth error message: %s", authErr.Message)
		return
	}
	var myErr *protocol.MySQLError
	if errors.As(err, &myErr) {
		require.Equal(t, code, myErr.Code, "mysql error message: %s", myErr.Message)
		return
	}
	t.Fatalf("expected error with MySQL code %d, got %T: %v", code, err, err)
}

func databaseNames(rs *protocol.ResultSet) []string {
	names := make([]string, 0, len(rs.Rows))
	for _, row := range rs.Rows {
		names = append(names, row[0].(string))
	}
	return names
}

func TestAuthzShowDatabasesVisibility(t *testing.T) {
	h, mgr := setupAuthzHandler(t)

	// Limited account sees only its grant; the system database and the two
	// other user databases disappear from the listing.
	rs, err := h.HandleQuery(authzSession(t, mgr, "appuser", "app-pw"), "SHOW DATABASES", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"appa"}, databaseNames(rs))

	// Wildcard admin sees every user database but never the internal one.
	rs, err = h.HandleQuery(authzSession(t, mgr, "admin", "admin-pw"), "SHOW DATABASES", nil)
	require.NoError(t, err)
	names := databaseNames(rs)
	require.Contains(t, names, "appa")
	require.Contains(t, names, "appb")
	require.Contains(t, names, "shared")
	require.NotContains(t, names, db.SystemDatabaseName)
}

func TestAuthzUseDatabase(t *testing.T) {
	h, mgr := setupAuthzHandler(t)
	sess := authzSession(t, mgr, "appuser", "app-pw")

	_, err := h.HandleQuery(sess, "USE appb", nil)
	requireMySQLError(t, err, mysqlcode.ErrCodeDBAccessDenied)
	require.Empty(t, sess.CurrentDatabase)

	_, err = h.HandleQuery(sess, "USE ghostdb", nil)
	requireMySQLError(t, err, mysqlcode.ErrCodeBadDB)

	_, err = h.HandleQuery(sess, "USE appa", nil)
	require.NoError(t, err)
	require.Equal(t, "appa", sess.CurrentDatabase)
}

func TestAuthzStatementGrants(t *testing.T) {
	h, mgr := setupAuthzHandler(t)

	// Read on a database outside the grant is denied before the data is
	// touched.
	_, err := h.HandleQuery(authzSession(t, mgr, "appuser", "app-pw"), "SELECT * FROM appb.t1", nil)
	requireMySQLError(t, err, mysqlcode.ErrCodeDBAccessDenied)

	// A read-only account cannot write: 1142 for a table command.
	_, err = h.HandleQuery(authzSession(t, mgr, "ro", "ro-pw"), "INSERT INTO appa.t VALUES (1)", nil)
	requireMySQLError(t, err, mysqlcode.ErrCodeTableAccessDenied)

	// Access denial wins over read-only denial.
	_, err = h.HandleQuery(authzSession(t, mgr, "ro", "ro-pw"), "INSERT INTO appb.t VALUES (1)", nil)
	requireMySQLError(t, err, mysqlcode.ErrCodeDBAccessDenied)

	// DDL on an ungranted database is denied as well.
	_, err = h.HandleQuery(authzSession(t, mgr, "appuser", "app-pw"), "CREATE DATABASE otherdb", nil)
	requireMySQLError(t, err, mysqlcode.ErrCodeDBAccessDenied)
}

func TestAuthzInformationSchemaHidesSchemas(t *testing.T) {
	h, mgr := setupAuthzHandler(t)
	rs, err := h.HandleQuery(
		authzSession(t, mgr, "appuser", "app-pw"),
		"SELECT * FROM information_schema.schemata",
		nil,
	)
	require.NoError(t, err)
	// SCHEMA_NAME is the second column.
	for _, row := range rs.Rows {
		require.Equal(t, "appa", row[1], "unauthorized schema leaked through INFORMATION_SCHEMA")
	}
}

func TestAuthzClusterVirtualTableRestricted(t *testing.T) {
	h, mgr := setupAuthzHandler(t)

	_, err := h.HandleQuery(authzSession(t, mgr, "appuser", "app-pw"), "SELECT * FROM MARMOT_CLUSTER_NODES", nil)
	requireMySQLError(t, err, mysqlcode.ErrCodeTableAccessDenied)
}

func TestAuthzOpenModePreservedWithoutManager(t *testing.T) {
	tmpDir := t.TempDir()
	clock := hlc.NewClock(1)
	dbMgr, err := db.NewDatabaseManager(tmpDir, 1, clock)
	require.NoError(t, err)
	t.Cleanup(func() { dbMgr.Close() })
	require.NoError(t, dbMgr.MergeAutoIncBasesAndReleaseVotes(nil))
	require.NoError(t, dbMgr.CreateDatabase("appa"))
	require.NoError(t, dbMgr.CreateDatabase("appb"))

	h := coordinator.NewCoordinatorHandler(1, nil, nil, clock, dbMgr, coordinator.NewDDLLockManager(30*time.Second), nil, nil)

	// No SetAuthManager: open mode, an unauthenticated session sees every
	// database (historical behavior).
	rs, err := h.HandleQuery(&protocol.ConnectionSession{ConnID: 1, TranspilationEnabled: true}, "SHOW DATABASES", nil)
	require.NoError(t, err)
	names := databaseNames(rs)
	require.Contains(t, names, "appa")
	require.Contains(t, names, "appb")
}
