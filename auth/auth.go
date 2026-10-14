// Package auth authenticates MySQL-protocol client connections and authorizes
// the databases and statement kinds each connected account may use.
//
// When no accounts are configured the manager is disabled and Marmot keeps its
// historical open-access behavior; when at least one account is configured
// every connection must present valid mysql_native_password credentials and is
// confined to that account's grants.
package auth

import (
	"fmt"
	"net"
	"path"
	"sort"
	"strings"

	"github.com/maxpert/marmot/cfg"
	"github.com/maxpert/marmot/protocol/mysqlcode"
)

// SystemDatabaseName mirrors db.SystemDatabaseName. It is duplicated here to
// keep this package below db (db depends on protocol, which depends on this
// package). Marmot's internal bookkeeping database is never exposed to client
// accounts, even to wildcard accounts.
const SystemDatabaseName = "__marmot_system"

// Error carries a MySQL wire-protocol error code and SQLSTATE so callers can
// surface a privilege failure to clients exactly as MySQL would.
type Error struct {
	Code     uint16
	SQLState string
	Message  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("ERROR %d (%s): %s", e.Code, e.SQLState, e.Message)
}

// AccessDeniedError builds MySQL error 1045, the uniform login-failure message
// given for both unknown accounts and wrong passwords so the response cannot
// be used to enumerate account names.
func AccessDeniedError(user, host string, usingPassword bool) *Error {
	using := "NO"
	if usingPassword {
		using = "YES"
	}
	return &Error{
		Code:     mysqlcode.ErrCodeAccessDenied,
		SQLState: mysqlcode.SQLStateAccessDenied,
		Message:  fmt.Sprintf("Access denied for user '%s'@'%s' (using password: %s)", user, host, using),
	}
}

// DBAccessDeniedError builds MySQL error 1044 for use of a database the
// account has not been granted.
func DBAccessDeniedError(user, host, database string) *Error {
	return &Error{
		Code:     mysqlcode.ErrCodeDBAccessDenied,
		SQLState: mysqlcode.SQLStateSyntax,
		Message:  fmt.Sprintf("Access denied for user '%s'@'%s' to database '%s'", user, host, database),
	}
}

// CommandDeniedError builds MySQL error 1142 for a statement the account's
// read-only grant cannot perform.
func CommandDeniedError(user, host, command, table string) *Error {
	return &Error{
		Code:     mysqlcode.ErrCodeTableAccessDenied,
		SQLState: mysqlcode.SQLStateSyntax,
		Message:  fmt.Sprintf("%s command denied to user '%s'@'%s' for table '%s'", command, user, host, table),
	}
}

// Identity is the authenticated principal attached to one connection for its
// lifetime. It must not be mutated after issue.
type Identity struct {
	Name     string
	Host     string
	readOnly bool
	allowAll bool
	grants   []string // exact names or glob patterns ("*" folded into allowAll)
}

// IsAdmin reports the account holds the wildcard grant, i.e. may use every
// (user) database. Cluster-information virtual tables are restricted to admin
// accounts.
func (i *Identity) IsAdmin() bool {
	return i != nil && i.allowAll
}

// IsReadOnly reports the account may read but not mutate granted databases.
func (i *Identity) IsReadOnly() bool {
	return i != nil && i.readOnly
}

// CanAccess reports the account is granted the named database. Marmot's
// internal system database is never accessible. A nil identity (open mode)
// accesses everything.
func (i *Identity) CanAccess(database string) bool {
	if i == nil {
		return true
	}
	if database == "" || database == SystemDatabaseName {
		return false
	}
	if i.allowAll {
		return true
	}
	for _, grant := range i.grants {
		if grant == database {
			return true
		}
		if matched, err := path.Match(grant, database); err == nil && matched {
			return true
		}
	}
	return false
}

// VisibleDatabases drops database names the account must not see, preserving
// order. A nil identity sees everything.
func (i *Identity) VisibleDatabases(names []string) []string {
	if i == nil {
		return names
	}
	visible := make([]string, 0, len(names))
	for _, name := range names {
		if i.CanAccess(name) {
			visible = append(visible, name)
		}
	}
	return visible
}

type storedUser struct {
	stage2   []byte
	identity Identity
}

// Manager owns the configured accounts and performs authentication and
// authorization.
type Manager struct {
	enabled bool
	users   map[string]storedUser
}

// NewManager builds a Manager from configuration. It is called once at
// startup; configuration validation in cfg.Validate guarantees the accounts
// are well formed, but malformed hashes are still rejected here defensively.
func NewManager(users []cfg.MySQLUserConfiguration) (*Manager, error) {
	m := &Manager{users: make(map[string]storedUser)}
	if len(users) == 0 {
		return m, nil
	}

	for _, u := range users {
		name := strings.TrimSpace(u.Name)
		var stage2 []byte
		switch {
		case u.PasswordHash != "":
			raw, err := ParsePasswordHash(u.PasswordHash)
			if err != nil {
				return nil, fmt.Errorf("mysql.users %q: %w", name, err)
			}
			stage2 = raw
		default:
			stage2 = PasswordStage2(u.Password)
		}

		identity := Identity{
			Name:     name,
			readOnly: u.ReadOnly,
			grants:   make([]string, 0, len(u.Databases)),
		}
		for _, db := range u.Databases {
			db = strings.TrimSpace(db)
			if db == wildcardAll {
				identity.allowAll = true
			}
			identity.grants = append(identity.grants, db)
		}

		m.users[name] = storedUser{stage2: stage2, identity: identity}
	}
	m.enabled = true
	return m, nil
}

// Enabled reports whether connections must authenticate. It is false only
// when no accounts are configured, preserving open access.
func (m *Manager) Enabled() bool {
	return m != nil && m.enabled
}

// AccountNames returns configured account names in stable order, for logging.
func (m *Manager) AccountNames() []string {
	if m == nil {
		return nil
	}
	names := make([]string, 0, len(m.users))
	for name := range m.users {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Authenticate validates a handshake login and returns the connection's
// identity. remoteAddr is the client's net address, used in MySQL-style
// user@host error messages.
func (m *Manager) Authenticate(username string, authResponse, salt []byte, remoteAddr string) (*Identity, error) {
	host := hostFromAddr(remoteAddr)
	usingPassword := len(authResponse) > 0

	u, ok := m.users[username]
	if !ok || !VerifyNativePassword(authResponse, salt, u.stage2) {
		return nil, AccessDeniedError(username, host, usingPassword)
	}

	identity := u.identity
	identity.Host = host
	return &identity, nil
}

// IdentityFor returns a copy of an account's identity for a connection that a
// trusted replica has already authenticated, so the leader can authorize
// requests the replica forwards on that client's behalf. host labels the
// identity in denial messages. It returns nil for an unknown account, and
// always nil while authentication is disabled (open mode).
func (m *Manager) IdentityFor(username, host string) *Identity {
	if !m.Enabled() {
		return nil
	}
	u, ok := m.users[username]
	if !ok {
		return nil
	}
	identity := u.identity
	identity.Host = host
	return &identity
}

// Authorize enforces a database grant for an authenticated identity. write
// selects a modification (INSERT/CREATE/...) versus a read. command and table
// shape the MySQL-compatible denial message. A nil identity is allowed only
// while the manager is disabled.
func (m *Manager) Authorize(identity *Identity, database, command, table string, write bool) error {
	if !m.Enabled() {
		return nil
	}
	name, host := "", ""
	if identity != nil {
		name, host = identity.Name, identity.Host
	}
	if !identity.CanAccess(database) {
		return DBAccessDeniedError(name, host, database)
	}
	if write && identity.IsReadOnly() {
		target := table
		if target == "" {
			// Database-level operation (CREATE/DROP DATABASE): MySQL reports
			// a database grant failure rather than a table one.
			return DBAccessDeniedError(name, host, database)
		}
		return CommandDeniedError(name, host, command, target)
	}
	return nil
}

const wildcardAll = "*"

// hostFromAddr extracts the host part of a remote address for user@host
// messages, tolerating addresses without ports.
func hostFromAddr(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	if remoteAddr == "" {
		return ""
	}
	return remoteAddr
}
