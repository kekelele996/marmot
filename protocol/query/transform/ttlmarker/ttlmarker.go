// Package ttlmarker records a table's row-expiry column in the replicated DDL
// text, and reads it back.
//
// A table opts into time-to-live cleanup with a MySQL table COMMENT directive:
//
//	CREATE TABLE sessions (
//	  id INTEGER PRIMARY KEY,
//	  expires_at INTEGER NOT NULL
//	) COMMENT='marmot:ttl=expires_at';
//
// SQLite has no table-option equivalent, and the transpiler strips every
// MySQL table option before the statement reaches it. So the directive rides
// in the stored DDL text as a block comment beside the table definition:
//
//	CREATE TABLE sessions (... /*M:TTL:expires_at*/)
//
// which SQLite preserves verbatim in sqlite_master.sql. The comment is table
// level (it sits immediately BEFORE the closing parenthesis of the table spec,
// between two tokens - a trailing comment after the spec is dropped by SQLite),
// so the integer-width marker scanner in intmarker never attributes it to a
// column: its body is not a width and parseMarkerBody rejects it. It shares intmarker's
// "/*M:" prefix on purpose: intmarker.Strip, which hides the markers from
// SHOW CREATE TABLE, removes every marker with that prefix, and its quote-aware
// scanner will never mistake this one for column structure.
//
// The marker travels in replicated DDL text, so every node derives the same
// policy from its own sqlite_master without a separate replicated metadata
// channel - the same reason the AUTO_INCREMENT width marker rides DDL text.
package ttlmarker

import (
	"regexp"
	"strings"
)

const (
	markerOpen  = "/*M:TTL:"
	markerClose = "*/"

	// DirectivePrefix is the token recognised inside a MySQL table COMMENT
	// option value, e.g. COMMENT='sessions; marmot:ttl=expires_at'. Matching
	// is case-insensitive and the token may sit anywhere in the comment text.
	DirectivePrefix = "marmot:ttl="
)

// identifierRE pins the columns a directive may name: an ordinary ASCII
// identifier, unquoted in both MySQL and SQLite. It deliberately excludes
// anything that would need quoting inside SQL or could terminate the block
// comment marker ("*", "/").
var identifierRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]*$`)

// ValidIdentifier reports whether name is a column name this package can encode
// in a marker.
func ValidIdentifier(name string) bool {
	return identifierRE.MatchString(name)
}

// Encode renders the table-level TTL marker for column, or "" when column is
// not encodable. A caller receiving "" must change nothing rather than emit an
// empty comment.
func Encode(column string) string {
	if !ValidIdentifier(column) {
		return ""
	}
	return markerOpen + column + markerClose
}

// Decode reads the table-level TTL marker from one table's sqlite_master.sql
// text and returns the named column. Quoted strings and non-marker comments
// are skipped, so a marker appearing inside a default value or a column
// comment is data, not a marker.
func Decode(createSQL string) (string, bool) {
	for i := 0; i < len(createSQL); i++ {
		if strings.HasPrefix(createSQL[i:], markerOpen) {
			end := strings.Index(createSQL[i+len(markerOpen):], markerClose)
			if end < 0 {
				return "", false
			}
			col := createSQL[i+len(markerOpen) : i+len(markerOpen)+end]
			if !ValidIdentifier(col) {
				return "", false
			}
			return col, true
		}
		if skip, next := skipNonCode(createSQL, i); skip {
			i = next - 1
		}
	}
	return "", false
}

// ExtractDirective reads the expiry column a table COMMENT value declares with
// marmot:ttl=<column>. The surrounding text is ignored and the directive is
// matched case-insensitively.
func ExtractDirective(comment string) (string, bool) {
	lower := strings.ToLower(comment)
	idx := strings.Index(lower, DirectivePrefix)
	if idx < 0 {
		return "", false
	}
	rest := comment[idx+len(DirectivePrefix):]
	// The directive ends at the first token delimiter MySQL permits inside a
	// COMMENT string that could otherwise glue onto the column name.
	end := 0
	for end < len(rest) && !isDelimiter(rest[end]) {
		end++
	}
	col := rest[:end]
	if !ValidIdentifier(col) {
		return "", false
	}
	return col, true
}

func isDelimiter(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', ',', ';', '"', '\'', '`':
		return true
	}
	return false
}

// skipNonCode reports whether position i begins a region that is not DDL
// structure, and where that region ends. A TTL marker is deliberately NOT
// skipped, exactly as intmarker treats its own markers.
func skipNonCode(s string, i int) (bool, int) {
	switch {
	case s[i] == '\'':
		return true, closingQuote(s, i, '\'')
	case s[i] == '"':
		return true, closingQuote(s, i, '"')
	case s[i] == '`':
		return true, closingQuote(s, i, '`')
	case strings.HasPrefix(s[i:], "--"):
		if nl := strings.IndexByte(s[i:], '\n'); nl >= 0 {
			return true, i + nl + 1
		}
		return true, len(s)
	case strings.HasPrefix(s[i:], "/*"):
		// Any other block comment is skipped; the loop only enters here for
		// comments that do not start with markerOpen.
		if close := strings.Index(s[i+2:], "*/"); close >= 0 {
			return true, i + 2 + close + 2
		}
		return true, len(s)
	}
	return false, i
}

// closingQuote finds the end of a quoted region, honouring SQL's
// doubled-quote escape.
func closingQuote(s string, start int, q byte) int {
	for i := start + 1; i < len(s); i++ {
		if s[i] != q {
			continue
		}
		if i+1 < len(s) && s[i+1] == q {
			i++
			continue
		}
		return i + 1
	}
	return len(s)
}
