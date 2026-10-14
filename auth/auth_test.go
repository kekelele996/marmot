package auth

import (
	"crypto/sha1"
	"strings"
	"testing"

	"github.com/maxpert/marmot/cfg"
	"github.com/maxpert/marmot/protocol/mysqlcode"
)

// clientScramble computes the response a MySQL client sends for password,
// given the server's 20-byte salt.
func clientScramble(t *testing.T, password string, salt []byte) []byte {
	t.Helper()
	stage1 := sha1.Sum([]byte(password))
	stage2 := sha1.Sum(stage1[:])

	h := sha1.New()
	h.Write(salt[:20])
	h.Write(stage2[:])
	saltDigest := h.Sum(nil)

	scramble := make([]byte, 20)
	for i := 0; i < 20; i++ {
		scramble[i] = stage1[i] ^ saltDigest[i]
	}
	return scramble
}

func TestNativePasswordRoundTrip(t *testing.T) {
	salt := GenerateSalt()

	if !VerifyNativePassword(clientScramble(t, "s3cr3t", salt[:]), salt[:], PasswordStage2("s3cr3t")) {
		t.Fatal("correct password scramble must verify")
	}

	wrong := clientScramble(t, "S3CR3T", salt[:])
	if VerifyNativePassword(wrong, salt[:], PasswordStage2("s3cr3t")) {
		t.Fatal("wrong password scramble must not verify")
	}

	otherSalt := GenerateSalt()
	if VerifyNativePassword(clientScramble(t, "s3cr3t", otherSalt[:]), salt[:], PasswordStage2("s3cr3t")) {
		t.Fatal("scramble computed against another salt must not verify")
	}

	if VerifyNativePassword(nil, salt[:], PasswordStage2("s3cr3t")) {
		t.Fatal("empty auth response must never authenticate a password account")
	}
	if VerifyNativePassword(make([]byte, 19), salt[:], PasswordStage2("s3cr3t")) {
		t.Fatal("short scramble must not verify")
	}
}

func TestGenerateSaltHasNoZeroBytesAndVaries(t *testing.T) {
	s1 := GenerateSalt()
	s2 := GenerateSalt()
	if s1 == s2 {
		t.Fatal("two salts must differ")
	}
	for _, b := range s1 {
		if b == 0 {
			t.Fatal("salt must not contain zero bytes")
		}
	}
	for _, b := range s2 {
		if b == 0 {
			t.Fatal("salt must not contain zero bytes")
		}
	}
}

func TestParsePasswordHash(t *testing.T) {
	stage2 := PasswordStage2("hunter2")
	mysqlHash := MySQLPasswordHash("hunter2")
	if !strings.HasPrefix(mysqlHash, "*") || len(mysqlHash) != 41 {
		t.Fatalf("PASSWORD() form must be * + 40 hex, got %q", mysqlHash)
	}

	parsed, err := ParsePasswordHash(mysqlHash)
	if err != nil {
		t.Fatalf("star form must parse: %v", err)
	}
	if string(parsed) != string(stage2) {
		t.Fatal("parsed hash must equal SHA1(SHA1(password))")
	}

	bare := strings.ToLower(mysqlHash[1:])
	parsed, err = ParsePasswordHash(bare)
	if err != nil {
		t.Fatalf("bare hex must parse: %v", err)
	}
	if string(parsed) != string(stage2) {
		t.Fatal("bare hex must parse to the same digest")
	}

	if _, err := ParsePasswordHash("*zz"); err == nil {
		t.Fatal("malformed hash must be rejected")
	}
	if _, err := ParsePasswordHash(strings.Repeat("z", 40)); err == nil {
		t.Fatal("non-hex hash must be rejected")
	}
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager([]cfg.MySQLUserConfiguration{
		{Name: "app_a", Password: "pw-a", Databases: []string{"appa"}},
		{Name: "app_b", Password: "pw-b", Databases: []string{"appb", "shared"}, ReadOnly: true},
		{Name: "tenant", Password: "pw-t", Databases: []string{"tenant_*"}},
		{Name: "admin", PasswordHash: MySQLPasswordHash("admin-pw"), Databases: []string{"*"}},
	})
	if err != nil {
		t.Fatalf("manager construction failed: %v", err)
	}
	return m
}

func TestManagerDisabledByDefault(t *testing.T) {
	m, err := NewManager(nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Enabled() {
		t.Fatal("manager without users must be disabled (open mode)")
	}
	if err := m.Authorize(nil, "anything", "SELECT", "", true); err != nil {
		t.Fatalf("disabled manager must authorize everything, got %v", err)
	}
}

func TestAuthenticate(t *testing.T) {
	m := newTestManager(t)
	salt := GenerateSalt()

	id, err := m.Authenticate("app_a", clientScramble(t, "pw-a", salt[:]), salt[:], "10.0.0.7:53124")
	if err != nil {
		t.Fatalf("valid login rejected: %v", err)
	}
	if id.Name != "app_a" || id.Host != "10.0.0.7" {
		t.Fatalf("identity fields wrong: %+v", id)
	}

	// Unknown user and wrong password give the identical 1045 response.
	for _, tc := range []struct {
		user string
		resp func() []byte
	}{
		{"ghost", func() []byte { return clientScramble(t, "pw-a", salt[:]) }},
		{"app_a", func() []byte { return clientScramble(t, "wrong", salt[:]) }},
		{"app_a", func() []byte { return nil }},
	} {
		_, err := m.Authenticate(tc.user, tc.resp(), salt[:], "10.0.0.7:53124")
		authErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("%s: expected *auth.Error, got %T", tc.user, err)
		}
		if authErr.Code != mysqlcode.ErrCodeAccessDenied || authErr.SQLState != mysqlcode.SQLStateAccessDenied {
			t.Fatalf("%s: expected 1045/28000, got %d/%s", tc.user, authErr.Code, authErr.SQLState)
		}
		if !strings.Contains(authErr.Message, "'app_a'@'10.0.0.7'") && !strings.Contains(authErr.Message, "'ghost'@'10.0.0.7'") {
			t.Fatalf("message must be MySQL-style user@host: %q", authErr.Message)
		}
	}

	// Password hash accounts authenticate identically.
	id, err = m.Authenticate("admin", clientScramble(t, "admin-pw", salt[:]), salt[:], "localhost:1")
	if err != nil {
		t.Fatalf("hash-configured login rejected: %v", err)
	}
	if !id.IsAdmin() {
		t.Fatal("wildcard account must be admin")
	}
}

func TestGrantsAndVisibility(t *testing.T) {
	m := newTestManager(t)
	salt := GenerateSalt()

	appA, err := m.Authenticate("app_a", clientScramble(t, "pw-a", salt[:]), salt[:], "h:1")
	if err != nil {
		t.Fatal(err)
	}
	appB, err := m.Authenticate("app_b", clientScramble(t, "pw-b", salt[:]), salt[:], "h:2")
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := m.Authenticate("tenant", clientScramble(t, "pw-t", salt[:]), salt[:], "h:3")
	if err != nil {
		t.Fatal(err)
	}

	// Exact grants
	if !appA.CanAccess("appa") || appA.CanAccess("appb") {
		t.Fatal("app_a must only see appa")
	}
	// Glob grant
	if !tenant.CanAccess("tenant_42") || tenant.CanAccess("tenant") || tenant.CanAccess("other") {
		t.Fatal("glob grant must match tenant_* only")
	}
	// Internal database is invisible to everyone, admin included
	for _, id := range []*Identity{appA, appB, tenant, tenantMustBeAdmin(t, m, salt[:])} {
		if id.CanAccess(SystemDatabaseName) {
			t.Fatalf("%s must never access %s", id.Name, SystemDatabaseName)
		}
		if id.CanAccess("") {
			t.Fatalf("%s must not be granted an empty database name", id.Name)
		}
	}

	// SHOW DATABASES style filtering
	all := []string{"appa", "appb", "shared", "tenant_1", "tenant_2", SystemDatabaseName}
	got := appB.VisibleDatabases(all)
	if len(got) != 2 || got[0] != "appb" || got[1] != "shared" {
		t.Fatalf("app_b visibility wrong: %v", got)
	}
	got = tenant.VisibleDatabases(all)
	if len(got) != 2 {
		t.Fatalf("tenant visibility wrong: %v", got)
	}

	// Read-write account
	if err := m.Authorize(appA, "appa", "INSERT", "t1", true); err != nil {
		t.Fatalf("app_a write on appa must pass: %v", err)
	}
	if err := m.Authorize(appA, "appb", "SELECT", "t1", false); err == nil {
		t.Fatal("app_a read on appb must be denied")
	}

	// Read-only account: reads allowed, writes denied with 1142 for a table
	if err := m.Authorize(appB, "shared", "SELECT", "t1", false); err != nil {
		t.Fatalf("read-only account must read granted db: %v", err)
	}
	err = m.Authorize(appB, "shared", "INSERT", "t1", true)
	cmdErr, ok := err.(*Error)
	if !ok || cmdErr.Code != mysqlcode.ErrCodeTableAccessDenied {
		t.Fatalf("expected 1142 table denial, got %v", err)
	}
	if !strings.Contains(cmdErr.Message, "INSERT command denied") {
		t.Fatalf("denial message must name the command: %q", cmdErr.Message)
	}
	// Database-level write denial (no table) is 1044
	err = m.Authorize(appB, "shared", "CREATE", "", true)
	dbErr, ok := err.(*Error)
	if !ok || dbErr.Code != mysqlcode.ErrCodeDBAccessDenied {
		t.Fatalf("expected 1044 database denial, got %v", err)
	}
}

func tenantMustBeAdmin(t *testing.T, m *Manager, salt []byte) *Identity {
	t.Helper()
	id, err := m.Authenticate("admin", clientScramble(t, "admin-pw", salt), salt, "h:4")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestNewManagerRejectsBadHash(t *testing.T) {
	_, err := NewManager([]cfg.MySQLUserConfiguration{
		{Name: "x", PasswordHash: "*not-a-hash", Databases: []string{"*"}},
	})
	if err == nil {
		t.Fatal("malformed configured hash must fail manager construction")
	}
}
