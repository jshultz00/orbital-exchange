// Package db opens the SQLite database and applies the schema.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// modernc.org/sqlite registers a pure-Go "sqlite" driver via database/sql.
	// No CGO required, so builds stay simple. The blank import is for the
	// driver registration side effect only.
	_ "modernc.org/sqlite"

	// schema.sql is embedded into the binary so the app can self-bootstrap
	// without needing the file to exist at runtime.
	_ "embed"
)

//go:embed schema.sql
var schemaSQL string

// Open opens (creating if needed) the SQLite database at path, applies the
// schema, and returns a connection pool. Caller is responsible for Close().
func Open(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	// Connection-string options:
	//   _pragma=foreign_keys(1)  enforce FK constraints (off by default in SQLite)
	//   _pragma=journal_mode(WAL) better concurrency: readers don't block writers
	//   _pragma=busy_timeout(5000) wait up to 5s if the DB is locked instead of failing
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := conn.Ping(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	if _, err := conn.Exec(schemaSQL); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	if err := migrate(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return conn, nil
}

// migrate runs idempotent ALTERs that bring older databases up to the current
// schema. CREATE TABLE IF NOT EXISTS in schema.sql cannot add columns to an
// existing table, so any column added after first release ships here too.
//
// Each ALTER is run with its "duplicate column" error treated as success, so
// the function is safe to run on every boot.
func migrate(conn *sql.DB) error {
	alters := []string{
		`ALTER TABLE vulnerabilities ADD COLUMN is_planted INTEGER NOT NULL DEFAULT 0`,
	}
	for _, stmt := range alters {
		if _, err := conn.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}
