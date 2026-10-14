package cfg

import (
	"strings"
	"testing"
)

func TestValidateMySQLUsers(t *testing.T) {
	valid := []MySQLUserConfiguration{
		{
			Name:      "app",
			Password:  "secret",
			Databases: []string{"appdb"},
		},
		{
			// MySQL PASSWORD() form
			Name:         "ro",
			PasswordHash: "*4DFF2E55F8B65B98B7B2D4D5C7A2F4E9B7A6C2A1",
			Databases:    []string{"appdb", "shared"},
			ReadOnly:     true,
		},
		{
			Name:      "admin",
			Password:  "admin",
			Databases: []string{"*"},
		},
	}
	if err := validateMySQLUsers(valid); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}

	tests := []struct {
		name  string
		users []MySQLUserConfiguration
		want  string
	}{
		{
			name:  "empty name",
			users: []MySQLUserConfiguration{{Password: "p", Databases: []string{"d"}}},
			want:  "name cannot be empty",
		},
		{
			name: "duplicate name",
			users: []MySQLUserConfiguration{
				{Name: "a", Password: "p", Databases: []string{"d"}},
				{Name: "a", Password: "p", Databases: []string{"d"}},
			},
			want: "not unique",
		},
		{
			name: "both password sources",
			users: []MySQLUserConfiguration{{
				Name: "a", Password: "p", PasswordHash: "*abc", Databases: []string{"d"},
			}},
			want: "not both",
		},
		{
			name: "no password",
			users: []MySQLUserConfiguration{{
				Name: "a", Databases: []string{"d"},
			}},
			want: "password or password_hash is required",
		},
		{
			name: "malformed hash",
			users: []MySQLUserConfiguration{{
				Name: "a", PasswordHash: "nope", Databases: []string{"d"},
			}},
			want: "40 hex chars",
		},
		{
			name: "non-hex hash",
			users: []MySQLUserConfiguration{{
				Name: "a", PasswordHash: strings.Repeat("z", 40), Databases: []string{"d"},
			}},
			want: "hexadecimal",
		},
		{
			name: "no grants",
			users: []MySQLUserConfiguration{{
				Name: "a", Password: "p",
			}},
			want: "at least one entry",
		},
		{
			name: "empty grant",
			users: []MySQLUserConfiguration{{
				Name: "a", Password: "p", Databases: []string{"  "},
			}},
			want: "empty entry",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMySQLUsers(tc.users)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestIsMySQLAuthEnabled(t *testing.T) {
	original := Config.MySQL.Users
	defer func() { Config.MySQL.Users = original }()

	Config.MySQL.Users = nil
	if IsMySQLAuthEnabled() {
		t.Fatal("auth must be disabled without users")
	}
	Config.MySQL.Users = []MySQLUserConfiguration{{Name: "a"}}
	if !IsMySQLAuthEnabled() {
		t.Fatal("auth must be enabled with at least one user")
	}
}
