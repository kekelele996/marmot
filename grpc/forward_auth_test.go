package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/maxpert/marmot/auth"
	"github.com/maxpert/marmot/cfg"
	"github.com/maxpert/marmot/coordinator"
	"github.com/maxpert/marmot/hlc"
	"github.com/maxpert/marmot/protocol/mysqlcode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAuthedForwardHandler(t *testing.T) (*ForwardHandler, *ForwardSessionManager, *auth.Manager) {
	t.Helper()
	initPipeline()

	nodeID := uint64(1)
	clock := hlc.NewClock(nodeID)
	sessionMgr := NewForwardSessionManager(60 * time.Second)
	mockDB := &mockForwardDBManager{databases: map[string]bool{"testdb": true}}
	coordHandler := coordinator.NewCoordinatorHandler(nodeID, nil, nil, clock, nil, nil, nil, nil)

	mgr, err := auth.NewManager([]cfg.MySQLUserConfiguration{
		{Name: "app", Password: "pw", Databases: []string{"testdb"}},
		{Name: "limited", Password: "pw", Databases: []string{"otherdb"}},
	})
	require.NoError(t, err)
	// In production the same manager is installed on both the forward
	// handler (identity resolution) and the coordinator handler (grants).
	coordHandler.SetAuthManager(mgr)

	handler := NewForwardHandler(nodeID, clock, sessionMgr, coordHandler, mockDB)
	handler.SetAuthManager(mgr)
	return handler, sessionMgr, mgr
}

func TestForwardHandler_RejectsUnauthenticatedRequest(t *testing.T) {
	handler, sessionMgr, _ := newAuthedForwardHandler(t)
	defer sessionMgr.Stop()

	for _, username := range []string{"", "ghost"} {
		req := &ForwardQueryRequest{
			ReplicaNodeId: 7,
			SessionId:     100,
			RequestId:     1,
			Database:      "testdb",
			Sql:           "INSERT INTO users VALUES (1)",
			Username:      username,
		}
		resp, err := handler.HandleForwardQuery(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp.Success, "user %q must be rejected", username)
		assert.Equal(t, uint32(mysqlcode.ErrCodeAccessDenied), resp.ErrorCode)
		assert.Equal(t, mysqlcode.SQLStateAccessDenied, resp.SqlState)
	}
}

func TestForwardHandler_EnforcesGrantsOnLeader(t *testing.T) {
	handler, sessionMgr, _ := newAuthedForwardHandler(t)
	defer sessionMgr.Stop()

	// "limited" is authenticated but has no grant on testdb: the leader's
	// coordinator refuses the forwarded write with 1044, proving the
	// forwarded identity reached the authorization gate.
	req := &ForwardQueryRequest{
		ReplicaNodeId: 7,
		SessionId:     101,
		RequestId:     1,
		Database:      "testdb",
		Sql:           "INSERT INTO users VALUES (1)",
		Username:      "limited",
	}
	resp, err := handler.HandleForwardQuery(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, uint32(mysqlcode.ErrCodeDBAccessDenied), resp.ErrorCode)

	// The leader-side session carried the resolved identity.
	session := sessionMgr.GetOrCreateSession(ForwardSessionKey{ReplicaNodeID: 7, SessionID: 101}, "testdb", nil)
	require.NotNil(t, session.ConnSession.Identity)
	assert.Equal(t, "limited", session.ConnSession.Identity.Name)
}

func TestForwardHandler_OpenModeAllowsAnonymous(t *testing.T) {
	// No auth manager: requests without a username stay accepted at entry.
	handler, sessionMgr := newTestForwardHandler()
	defer sessionMgr.Stop()
	initPipeline()

	// A BEGIN forwarded without a username is not an authentication failure
	// (transaction control runs through the nil-coordinator test harness
	// safely, unlike a write).
	req := &ForwardQueryRequest{
		ReplicaNodeId: 7,
		SessionId:     200,
		RequestId:     1,
		TxnControl:    ForwardTxnControl_FWD_TXN_BEGIN,
	}
	resp, err := handler.HandleForwardQuery(context.Background(), req)
	require.NoError(t, err)
	assert.NotEqual(t, uint32(mysqlcode.ErrCodeAccessDenied), resp.ErrorCode)
}
