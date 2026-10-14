package transform

import (
	"strings"
	"testing"

	"github.com/maxpert/marmot/protocol/query/transform/intmarker"
	"github.com/maxpert/marmot/protocol/query/transform/ttlmarker"
	"vitess.io/vitess/go/vt/sqlparser"
)

func transformCreate(t *testing.T, input string) ([]TranspiledStatement, error) {
	t.Helper()
	stmt, err := sqlparser.NewTestParser().Parse(input)
	if err != nil {
		t.Fatalf("failed to parse SQL: %v", err)
	}
	return (&CreateTableRule{}).Transform(stmt, nil, nil, "testdb", &SQLiteSerializer{})
}

func TestCreateTableRule_TTLCommentBecomesMarker(t *testing.T) {
	input := "CREATE TABLE sessions (id INT PRIMARY KEY, expires_at INT NOT NULL) COMMENT='marmot:ttl=expires_at'"
	results, err := transformCreate(t, input)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}
	mainSQL := results[0].SQL

	col, ok := ttlmarker.Decode(mainSQL)
	if !ok || col != "expires_at" {
		t.Fatalf("TTL marker = %q, %v; want expires_at in %q", col, ok, mainSQL)
	}

	// The marker is hidden from SHOW CREATE TABLE by the shared marker
	// stripper, exactly like the integer width markers.
	stripped := intmarker.Strip(mainSQL)
	if strings.Contains(stripped, "/*M:") {
		t.Errorf("SHOW CREATE text still carries the TTL marker: %q", stripped)
	}

	// The MySQL table option must not leak into SQLite DDL.
	if strings.Contains(strings.ToLower(mainSQL), "comment=") {
		t.Errorf("COMMENT option leaked into SQLite DDL: %q", mainSQL)
	}

	// The marker rides the DDL text SQLite stores verbatim. SQLite drops
	// trailing comments, so it has to sit inside the table spec, between
	// tokens.
	if !strings.HasSuffix(strings.TrimSpace(mainSQL), "*/)") {
		t.Errorf("marker should end the table spec, got %q", mainSQL)
	}
}

func TestCreateTableRule_TTLDirectiveInsideLargerComment(t *testing.T) {
	input := "CREATE TABLE sessions (id INT PRIMARY KEY, expire_at INT) COMMENT='session store; marmot:ttl=expire_at; v1'"
	results, err := transformCreate(t, input)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}
	col, ok := ttlmarker.Decode(results[0].SQL)
	if !ok || col != "expire_at" {
		t.Fatalf("TTL marker = %q, %v; want expire_at", col, ok)
	}
}

func TestCreateTableRule_TTLUnknownColumnRejected(t *testing.T) {
	input := "CREATE TABLE sessions (id INT PRIMARY KEY) COMMENT='marmot:ttl=expires_at'"
	if _, err := transformCreate(t, input); err == nil {
		t.Fatal("Transform should reject a TTL directive naming a missing column")
	}
}

func TestCreateTableRule_PlainCommentHasNoMarker(t *testing.T) {
	input := "CREATE TABLE sessions (id INT PRIMARY KEY) COMMENT='user sessions'"
	results, err := transformCreate(t, input)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}
	if _, ok := ttlmarker.Decode(results[0].SQL); ok {
		t.Fatalf("plain COMMENT must not produce a TTL marker: %q", results[0].SQL)
	}
}
