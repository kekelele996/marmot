package coordinator

import (
	"errors"

	"github.com/maxpert/marmot/protocol"
	"github.com/rs/zerolog/log"
)

// SystemDatabaseName must match db.SystemDatabaseName (avoid import cycle)
const SystemDatabaseName = "__marmot_system"

var ErrSystemDatabaseProtected = errors.New("cannot drop system database")

// handleShowDatabases returns the databases the connected account is allowed
// to see (all of them in open mode).
func (h *CoordinatorHandler) handleShowDatabases(session *protocol.ConnectionSession) (*protocol.ResultSet, error) {
	if h.dbManager == nil {
		// Fallback if dbManager not set
		return &protocol.ResultSet{
			Columns: []protocol.ColumnDef{{Name: "Database", Type: 0xFD}},
			Rows:    [][]interface{}{{"marmot"}},
		}, nil
	}

	return h.metadata.HandleShowDatabases(h.schemaVisibility(session))
}

// handleShowEngines returns fake MySQL engine list for compatibility
func (h *CoordinatorHandler) handleShowEngines() (*protocol.ResultSet, error) {
	return &protocol.ResultSet{
		Columns: []protocol.ColumnDef{
			{Name: "Engine", Type: 0xFD},
			{Name: "Support", Type: 0xFD},
			{Name: "Comment", Type: 0xFD},
			{Name: "Transactions", Type: 0xFD},
			{Name: "XA", Type: 0xFD},
			{Name: "Savepoints", Type: 0xFD},
		},
		Rows: [][]interface{}{
			{"InnoDB", "DEFAULT", "Marmot SQLite engine with InnoDB compatibility", "YES", "NO", "YES"},
		},
	}, nil
}

// handleUseDatabase changes the current database for the session. Existence
// and grant checks have already run through AuthorizeDatabase by the time
// this is reached.
func (h *CoordinatorHandler) handleUseDatabase(session *protocol.ConnectionSession, dbName string) (*protocol.ResultSet, error) {
	if h.dbManager != nil && !h.dbManager.DatabaseExists(dbName) {
		return nil, errors.New("database does not exist: " + dbName)
	}

	session.CurrentDatabase = dbName
	log.Debug().Str("database", dbName).Uint64("conn_id", session.ConnID).Msg("Switched database")

	return nil, nil
}
