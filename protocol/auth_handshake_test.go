package protocol

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/maxpert/marmot/auth"
	"github.com/maxpert/marmot/cfg"
	"github.com/stretchr/testify/require"
)

// authMockHandler wraps mockHandler with a grant-backed database authorizer.
type authMockHandler struct {
	*mockHandler
	mgr      *auth.Manager
	existing map[string]bool
}

func (h *authMockHandler) AuthorizeDatabase(session *ConnectionSession, database string) error {
	if !h.existing[database] {
		return NewMySQLError(ErrCodeBadDB, SQLStateSyntax, "Unknown database '"+database+"'")
	}
	if !h.mgr.Enabled() {
		return nil
	}
	return h.mgr.Authorize(session.Identity, database, "USE", "", false)
}

func newAuthTestServer(t *testing.T) (*MySQLServer, *auth.Manager) {
	t.Helper()
	mgr, err := auth.NewManager([]cfg.MySQLUserConfiguration{
		{Name: "appuser", Password: "app-pw", Databases: []string{"appdb"}},
		{Name: "readonly", Password: "ro-pw", Databases: []string{"appdb"}, ReadOnly: true},
	})
	require.NoError(t, err)

	handler := &authMockHandler{
		mockHandler: &mockHandler{},
		mgr:         mgr,
		// "secret" exists but is not granted to the test account, so entry
		// fails the grant check (1044); "ghostdb" does not exist at all
		// (1049).
		existing: map[string]bool{"appdb": true, "secret": true},
	}
	server := NewMySQLServer("127.0.0.1:0", "", 0, handler)
	server.SetAuthenticator(mgr)
	require.NoError(t, server.Start())
	t.Cleanup(server.Stop)
	return server, mgr
}

// parseServerSalt extracts the 20-byte mysql_native_password salt from an
// Initial Handshake packet payload.
func parseServerSalt(t *testing.T, p []byte) []byte {
	t.Helper()
	require.Equal(t, byte(10), p[0], "expected protocol v10 handshake")
	null := bytes.IndexByte(p[1:], 0) + 1 // end of server version
	require.Positive(t, null)

	salt1Off := null + 1 + 4 // after version and connection id
	// filler(1) lowerCaps(2) charset(1) status(2) upperCaps(2) authLen(1) reserved(10)
	salt2Off := salt1Off + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
	salt := make([]byte, 20)
	copy(salt[:8], p[salt1Off:salt1Off+8])
	copy(salt[8:], p[salt2Off:salt2Off+12])
	for _, b := range salt {
		require.NotZero(t, b, "handshake salt must contain no zero bytes")
	}
	return salt
}

func nativeScramble(password string, salt []byte) []byte {
	stage1 := sha1.Sum([]byte(password))
	stage2 := sha1.Sum(stage1[:])
	h := sha1.New()
	h.Write(salt)
	h.Write(stage2[:])
	digest := h.Sum(nil)
	out := make([]byte, 20)
	for i := 0; i < 20; i++ {
		out[i] = stage1[i] ^ digest[i]
	}
	return out
}

// sendTestHandshake writes a handshake packet on a test connection, the way
// handleConnection does with a live one.
func sendTestHandshake(server *MySQLServer, conn net.Conn) error {
	salt := auth.GenerateSalt()
	return server.writeHandshake(conn, &ConnectionSession{ConnID: 1}, salt[:])
}

// rawHandshake performs a HandshakeResponse41 login and returns the server's
// seq=2 response payload.
func rawHandshake(t *testing.T, conn net.Conn, user, password, database string) []byte {
	t.Helper()
	handshake := readMySQLPacket(t, conn)
	salt := parseServerSalt(t, handshake)

	caps := uint32(0x0000a201) // PROTOCOL_41 | LONG_PASSWORD | SECURE_CONNECTION
	if database != "" {
		caps |= 0x00000008 // CLIENT_CONNECT_WITH_DB
	}

	var resp []byte
	capBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(capBytes, caps)
	resp = append(resp, capBytes...)
	resp = append(resp, 0, 0, 0, 1) // max packet size
	resp = append(resp, 45)         // charset
	resp = append(resp, make([]byte, 23)...)
	resp = append(resp, user+"\x00"...)
	if password == "" {
		resp = append(resp, 0)
	} else {
		scramble := nativeScramble(password, salt)
		resp = append(resp, byte(len(scramble)))
		resp = append(resp, scramble...)
	}
	if database != "" {
		resp = append(resp, database+"\x00"...)
	}
	writeMySQLPacket(t, conn, 1, resp)
	return readMySQLPacket(t, conn)
}

func errCode(payload []byte) uint16 {
	return binary.LittleEndian.Uint16(payload[1:3])
}

func TestHandshakeAuthentication(t *testing.T) {
	server, _ := newAuthTestServer(t)
	addr := server.listeners[0].Addr().String()

	dial := func(t *testing.T) net.Conn {
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		return conn
	}

	t.Run("valid credentials accepted", func(t *testing.T) {
		resp := rawHandshake(t, dial(t), "appuser", "app-pw", "")
		require.Equal(t, byte(0x00), resp[0], "expected OK packet")
	})

	t.Run("wrong password rejected with 1045", func(t *testing.T) {
		resp := rawHandshake(t, dial(t), "appuser", "nope", "")
		require.Equal(t, byte(0xFF), resp[0], "expected ERR packet")
		require.Equal(t, uint16(ErrCodeAccessDenied), errCode(resp))
	})

	t.Run("unknown user rejected with 1045", func(t *testing.T) {
		resp := rawHandshake(t, dial(t), "ghost", "app-pw", "")
		require.Equal(t, byte(0xFF), resp[0])
		require.Equal(t, uint16(ErrCodeAccessDenied), errCode(resp))
	})

	t.Run("empty password rejected for password account", func(t *testing.T) {
		resp := rawHandshake(t, dial(t), "appuser", "", "")
		require.Equal(t, byte(0xFF), resp[0])
		require.Equal(t, uint16(ErrCodeAccessDenied), errCode(resp))
	})

	t.Run("authorized handshake database accepted", func(t *testing.T) {
		resp := rawHandshake(t, dial(t), "appuser", "app-pw", "appdb")
		require.Equal(t, byte(0x00), resp[0])
	})

	t.Run("unauthorized handshake database rejected with 1044", func(t *testing.T) {
		resp := rawHandshake(t, dial(t), "appuser", "app-pw", "secret")
		require.Equal(t, byte(0xFF), resp[0])
		require.Equal(t, uint16(ErrCodeDBAccessDenied), errCode(resp))
	})

	t.Run("unknown handshake database rejected with 1049", func(t *testing.T) {
		resp := rawHandshake(t, dial(t), "appuser", "app-pw", "ghostdb")
		require.Equal(t, byte(0xFF), resp[0])
		require.Equal(t, uint16(ErrCodeBadDB), errCode(resp))
	})
}

func TestCOMInitDBAuthorization(t *testing.T) {
	server, _ := newAuthTestServer(t)
	addr := server.listeners[0].Addr().String()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	resp := rawHandshake(t, conn, "appuser", "app-pw", "")
	require.Equal(t, byte(0x00), resp[0])

	// USE secret -> denied
	writeMySQLPacket(t, conn, 0, append([]byte{0x02}, "secret"...))
	denied := readMySQLPacket(t, conn)
	require.Equal(t, byte(0xFF), denied[0])
	require.Equal(t, uint16(ErrCodeDBAccessDenied), errCode(denied))

	// USE appdb -> OK
	writeMySQLPacket(t, conn, 0, append([]byte{0x02}, "appdb"...))
	ok := readMySQLPacket(t, conn)
	require.Equal(t, byte(0x00), ok[0])

	// COM_QUIT to close cleanly
	_ = writeAndIgnore(conn, []byte{0x01})
}

func writeAndIgnore(conn net.Conn, payload []byte) error {
	header := []byte{byte(len(payload)), 0, 0, 0}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	if err == io.EOF {
		return nil
	}
	return err
}

func TestOpenModeStillAcceptsEverything(t *testing.T) {
	// No authenticator installed: legacy behavior must be preserved.
	server := NewMySQLServer("127.0.0.1:0", "", 0, &mockHandler{})
	require.NoError(t, server.Start())
	defer server.Stop()

	conn, err := net.Dial("tcp", server.listeners[0].Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	resp := completeHandshake(t, conn)
	require.Equal(t, byte(0x00), resp[0], "open mode must accept root with no password")
}
