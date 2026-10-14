package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// captureLogs redirects the global zerolog logger to an in-memory buffer at
// the given level and returns the buffer plus a restore function.
func captureLogs(t *testing.T, level zerolog.Level) (*bytes.Buffer, func()) {
	t.Helper()
	prev := log.Logger
	var buf bytes.Buffer
	log.Logger = zerolog.New(&buf).Level(level)
	return &buf, func() { log.Logger = prev }
}

// parseLastLogRecord decodes the final non-empty JSON log line in buf.
func parseLastLogRecord(t *testing.T, buf *bytes.Buffer) map[string]interface{} {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	require.NotEmpty(t, lines, "expected at least one log record")
	var rec map[string]interface{}
	require.NoError(t, json.Unmarshal(lines[len(lines)-1], &rec))
	return rec
}

func loggingTestSession() *ConnectionSession {
	return &ConnectionSession{
		ConnID:          42,
		RemoteAddr:      "10.0.0.7:51234",
		CurrentDatabase: "shop",
	}
}

func TestObserveQuerySlowQueryEmitsWarnWithSourceAndTiming(t *testing.T) {
	buf, restore := captureLogs(t, zerolog.InfoLevel)
	defer restore()

	server := NewMySQLServer("127.0.0.1:0", "", 0, &mockHandler{})
	server.SetQueryLogConfig(false, true, 100*time.Millisecond, defaultQueryLogMaxLength)

	rs := &ResultSet{
		Columns: []ColumnDef{{Name: "x", Type: ColumnTypeVarString}},
		Rows:    [][]interface{}{{"a"}, {"b"}},
	}
	// Pretend handling started 250ms ago, well over the 100ms threshold.
	start := time.Now().Add(-250 * time.Millisecond)
	server.observeQuery(loggingTestSession(), "SELECT * FROM orders", queryProtocolText, 0, start, rs, nil)

	rec := parseLastLogRecord(t, buf)
	require.Equal(t, "warn", rec["level"])
	require.Equal(t, "Slow query detected", rec["message"])
	require.EqualValues(t, 42, rec["conn_id"])
	require.Equal(t, "10.0.0.7:51234", rec["remote"])
	require.Equal(t, "shop", rec["database"])
	require.Equal(t, "text", rec["protocol"])
	require.Equal(t, "SELECT * FROM orders", rec["query"])
	require.EqualValues(t, 2, rec["rows_returned"])

	durationMS, ok := rec["duration_ms"].(float64)
	require.True(t, ok, "duration_ms missing or not numeric: %v", rec)
	require.GreaterOrEqual(t, durationMS, 250.0)
	require.Less(t, durationMS, 1000.0)
}

func TestObserveQueryFastQueryHiddenAtInfoLevelWithoutQueryLog(t *testing.T) {
	buf, restore := captureLogs(t, zerolog.InfoLevel)
	defer restore()

	server := NewMySQLServer("127.0.0.1:0", "", 0, &mockHandler{})
	server.SetQueryLogConfig(false, true, time.Hour, defaultQueryLogMaxLength)

	server.observeQuery(loggingTestSession(), "SELECT 1", queryProtocolText, 0, time.Now(),
		&ResultSet{Columns: []ColumnDef{{Name: "x"}}, Rows: [][]interface{}{{"1"}}}, nil)

	// Fast queries land at debug level, which info-level logging discards.
	require.Empty(t, bytes.TrimSpace(buf.Bytes()), "fast query must not log at info level when query log is disabled")
}

func TestObserveQueryQueryLogEnabledEmitsInfoRecord(t *testing.T) {
	buf, restore := captureLogs(t, zerolog.InfoLevel)
	defer restore()

	server := NewMySQLServer("127.0.0.1:0", "", 0, &mockHandler{})
	server.SetQueryLogConfig(true, false, 0, defaultQueryLogMaxLength)

	server.observeQuery(loggingTestSession(), "UPDATE carts SET qty = 2", queryProtocolPrepared, 1, time.Now(),
		&ResultSet{RowsAffected: 5}, nil)

	rec := parseLastLogRecord(t, buf)
	require.Equal(t, "info", rec["level"])
	require.Equal(t, "Query executed", rec["message"])
	require.Equal(t, "prepared", rec["protocol"])
	require.EqualValues(t, 1, rec["params"])
	require.EqualValues(t, 5, rec["rows_affected"])
	_, hasRowsReturned := rec["rows_returned"]
	require.False(t, hasRowsReturned)
}

func TestObserveQuerySlowLoggingDisabledNeverWarns(t *testing.T) {
	buf, restore := captureLogs(t, zerolog.InfoLevel)
	defer restore()

	server := NewMySQLServer("127.0.0.1:0", "", 0, &mockHandler{})
	server.SetQueryLogConfig(false, false, time.Millisecond, defaultQueryLogMaxLength)

	start := time.Now().Add(-time.Second)
	server.observeQuery(loggingTestSession(), "SELECT SLEEP(1)", queryProtocolText, 0, start, nil, nil)

	require.Empty(t, bytes.TrimSpace(buf.Bytes()), "slow log disabled must suppress the warn record at info level")
}

func TestObserveQueryIncludesError(t *testing.T) {
	buf, restore := captureLogs(t, zerolog.DebugLevel)
	defer restore()

	server := NewMySQLServer("127.0.0.1:0", "", 0, &mockHandler{})
	server.SetQueryLogConfig(false, false, time.Hour, defaultQueryLogMaxLength)

	server.observeQuery(loggingTestSession(), "SELECT * FROM missing", queryProtocolText, 0, time.Now(),
		nil, errors.New("no such table: missing"))

	rec := parseLastLogRecord(t, buf)
	require.Equal(t, "debug", rec["level"])
	require.Equal(t, "no such table: missing", rec["error"])
}

func TestTruncateQueryIsRuneSafe(t *testing.T) {
	server := NewMySQLServer("127.0.0.1:0", "", 0, &mockHandler{})
	server.SetQueryLogConfig(false, false, time.Hour, 5)

	short := "abc"
	require.Equal(t, short, server.truncateQuery(short), "queries at or under the limit must be unchanged")

	// 15 multibyte runes must be cut to 5 whole runes plus the marker.
	long := "慢查询日志记录截断测试用例文本"
	got := server.truncateQuery(long)
	require.True(t, len(got) > 5)
	require.Equal(t, "慢查询日志...(truncated)", got)
	require.True(t, utf8.ValidString(got), "truncation must not split a multibyte rune")

	// A negative limit disables truncation entirely.
	server.SetQueryLogConfig(false, false, time.Hour, -1)
	require.Equal(t, long, server.truncateQuery(long))
}

// slowMockHandler sleeps before answering so the real processQuery path
// measures a duration over the slow-query threshold.
type slowMockHandler struct {
	delay time.Duration
}

func (h *slowMockHandler) HandleQuery(session *ConnectionSession, sql string, params []interface{}) (*ResultSet, error) {
	time.Sleep(h.delay)
	return &ResultSet{RowsAffected: 7}, nil
}

func TestProcessQueryLogsSourceAndSlowDurationEndToEnd(t *testing.T) {
	buf, restore := captureLogs(t, zerolog.InfoLevel)
	defer restore()

	handler := &slowMockHandler{delay: 30 * time.Millisecond}
	server := NewMySQLServer("127.0.0.1:0", "", 0, handler)
	server.SetQueryLogConfig(false, true, 20*time.Millisecond, defaultQueryLogMaxLength)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan struct{})
	go func() {
		session := &ConnectionSession{
			ConnID:          99,
			RemoteAddr:      "192.168.1.50:40012",
			CurrentDatabase: "analytics",
		}
		server.processQuery(serverConn, session, "UPDATE hits SET n = n + 1")
		close(done)
	}()

	// Drain the OK packet so the server's response write completes and the
	// deferred request record is emitted.
	resp := mustReadPacket(t, clientConn)
	require.Equal(t, byte(0x00), resp[0], "expected OK packet")
	<-done

	rec := parseLastLogRecord(t, buf)
	require.Equal(t, "warn", rec["level"])
	require.Equal(t, "Slow query detected", rec["message"])
	require.EqualValues(t, 99, rec["conn_id"])
	require.Equal(t, "192.168.1.50:40012", rec["remote"])
	require.Equal(t, "analytics", rec["database"])
	require.Equal(t, "UPDATE hits SET n = n + 1", rec["query"])
	require.EqualValues(t, 7, rec["rows_affected"])

	durationMS, ok := rec["duration_ms"].(float64)
	require.True(t, ok)
	require.GreaterOrEqual(t, durationMS, 30.0)
}
