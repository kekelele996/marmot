package transform

import (
	"fmt"
	"strings"

	"github.com/maxpert/marmot/protocol/query/transform/ttlmarker"
	"vitess.io/vitess/go/vt/sqlparser"
)

// CreateTableRule transforms MySQL CREATE TABLE to SQLite-compatible form:
//   - Strips MySQL-specific column options (COLLATE, COMMENT)
//   - Strips MySQL-specific table options (ENGINE, CHARSET, COLLATE)
//   - Extracts non-primary, non-unique KEY/INDEX definitions into separate CREATE INDEX statements
//   - Keeps PRIMARY KEY definitions in the CREATE TABLE
//   - Keeps UNIQUE KEY definitions in the CREATE TABLE (converted to CONSTRAINT by serializer)
//   - Strips column length specifications: KEY idx (col(191)) → col
//   - Skips FULLTEXT/SPATIAL indexes (passed through to serializer)
type CreateTableRule struct {
}

func (r *CreateTableRule) Name() string {
	return "CreateTable"
}

func (r *CreateTableRule) Priority() int {
	return 10
}

func (r *CreateTableRule) Transform(stmt sqlparser.Statement, params []interface{}, schema SchemaProvider, database string, serializer Serializer) ([]TranspiledStatement, error) {
	create, ok := stmt.(*sqlparser.CreateTable)
	if !ok {
		return nil, ErrRuleNotApplicable
	}

	if create.TableSpec == nil {
		return nil, ErrRuleNotApplicable
	}

	tableName := create.Table.Name.String()
	var indexesToExtract []*sqlparser.IndexDefinition
	var remainingIndexes []*sqlparser.IndexDefinition

	for _, idx := range create.TableSpec.Indexes {
		if r.shouldExtractIndex(idx) {
			indexesToExtract = append(indexesToExtract, idx)
		} else {
			remainingIndexes = append(remainingIndexes, idx)
		}
	}

	create.TableSpec.Indexes = remainingIndexes

	// A table COMMENT may carry the row-expiry directive (marmot:ttl=<column>).
	// Extract it before the MySQL-specific table options are dropped, and
	// validate it names a column this CREATE declares.
	ttlColumn := ttlColumnFromOptions(create.TableSpec.Options)
	if ttlColumn != "" && !createDeclaresColumn(create, ttlColumn) {
		return nil, fmt.Errorf(
			"table COMMENT declares %s%q but the table has no column named %q",
			ttlmarker.DirectivePrefix, ttlColumn, ttlColumn)
	}

	// Clear MySQL-specific table options (ENGINE, CHARSET, COLLATE, COMMENT)
	create.TableSpec.Options = nil

	// Process columns: strip MySQL-specific options
	for _, col := range create.TableSpec.Columns {
		stripMySQLColumnType(col.Type)
	}

	// Build results
	var results []TranspiledStatement

	mainSQL := serializer.Serialize(create)
	if ttlColumn != "" {
		// The marker rides the replicated DDL text into every node's
		// sqlite_master.sql. SQLite drops comments after the statement's
		// final token, so the marker has to sit BETWEEN tokens: immediately
		// before the ')' that closes the table spec.
		mainSQL = insertTableMarker(mainSQL, ttlmarker.Encode(ttlColumn))
	}
	results = append(results, TranspiledStatement{SQL: mainSQL, Params: params})

	// Add CREATE INDEX statements (no params for DDL)
	for _, idx := range indexesToExtract {
		indexSQL := r.buildCreateIndex(tableName, idx)
		results = append(results, TranspiledStatement{SQL: indexSQL, Params: nil})
	}

	return results, nil
}

func (r *CreateTableRule) shouldExtractIndex(idx *sqlparser.IndexDefinition) bool {
	info := idx.Info
	if info == nil {
		return false
	}

	if info.Type == sqlparser.IndexTypePrimary {
		return false
	}

	if info.Type == sqlparser.IndexTypeFullText || info.Type == sqlparser.IndexTypeSpatial {
		return false
	}

	// Keep UNIQUE indexes inline (don't extract them)
	if info.IsUnique() {
		return false
	}

	return true
}

// insertTableMarker places a table-level marker comment immediately before the
// ')' that closes the CREATE TABLE spec. It cannot trail the statement: SQLite
// stores sqlite_master.sql with trailing comments removed, while a comment
// between two tokens survives verbatim.
func insertTableMarker(createSQL, marker string) string {
	trimmed := strings.TrimRight(createSQL, " \t\r\n;")
	if !strings.HasSuffix(trimmed, ")") {
		// An unfamiliar serializer shape: fall back to appending rather than
		// corrupting the statement.
		return trimmed + " " + marker
	}
	return trimmed[:len(trimmed)-1] + " " + marker + ")"
}

// ttlColumnFromOptions reads the marmot:ttl=&lt;column&gt; directive from a CREATE
// TABLE's COMMENT table option, if it carries one. Every other MySQL table
// option is irrelevant to TTL and is dropped later along with the whole
// option list.
func ttlColumnFromOptions(opts sqlparser.TableOptions) string {
	for _, opt := range opts {
		if opt == nil || opt.Value == nil || !strings.EqualFold(opt.Name, "comment") {
			continue
		}
		if col, ok := ttlmarker.ExtractDirective(opt.Value.Val); ok {
			return col
		}
	}
	return ""
}

// createDeclaresColumn reports whether create declares a column of the given
// name. Identifiers compare case-insensitively, the way SQLite resolves them.
func createDeclaresColumn(create *sqlparser.CreateTable, column string) bool {
	for _, col := range create.TableSpec.Columns {
		if strings.EqualFold(col.Name.String(), column) {
			return true
		}
	}
	return false
}

// buildCreateIndex generates a SQLite CREATE INDEX statement for the given index definition.
// Precondition: idx.Info must not be nil (enforced by shouldExtractIndex filter).
func (r *CreateTableRule) buildCreateIndex(tableName string, idx *sqlparser.IndexDefinition) string {
	if idx.Info == nil {
		return ""
	}

	var sb strings.Builder

	sb.WriteString("CREATE ")

	if idx.Info.IsUnique() {
		sb.WriteString("UNIQUE ")
	}

	sb.WriteString("INDEX IF NOT EXISTS ")

	indexName := idx.Info.Name.String()
	sb.WriteString(indexName)

	sb.WriteString(" ON ")
	sb.WriteString(tableName)

	sb.WriteString(" (")
	for i, col := range idx.Columns {
		if i > 0 {
			sb.WriteString(", ")
		}
		colName := col.Column.String()
		sb.WriteString(colName)
	}
	sb.WriteString(")")

	return sb.String()
}
