// Package seed loads initial catalog, OWASP categories, and vulnerability-
// tracker data into the database. It is idempotent and safe to run on every
// boot:
//
//   - Categories: upsert by id; static metadata only.
//   - Vulnerabilities: upsert by id. Static fields (category, title, etc.)
//     are refreshed from JSON; per-run progress fields (status,
//     discovered_at, notes) are preserved. This lets future specs append
//     rows or tweak copy without wiping discovered state.
//   - Products: INSERT OR IGNORE by slug. Existing rows are untouched, so
//     prices/stock don't reset on every boot. A full re-seed of the catalog
//     requires wiping the DB (scripts/wipe-db.sh).
package seed

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Default seeded user accounts. Documented in README. Idempotent: a row is
// only inserted if its username does not already exist, so a password change
// in the DB survives subsequent reseeds.
var defaultUsers = []struct {
	Username string
	Password string
	IsAdmin  bool
}{
	{Username: "command", Password: "stationcommand", IsAdmin: true},
	{Username: "ryland", Password: "hailmary42", IsAdmin: false},
}

//go:embed categories.json
var categoriesJSON []byte

//go:embed vulnerabilities.json
var vulnerabilitiesJSON []byte

//go:embed products.json
var productsJSON []byte

type category struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SortOrder int    `json:"sort_order"`
}

type vulnerability struct {
	ID          string `json:"id"`
	CategoryID  string `json:"category_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Difficulty  string `json:"difficulty"`
	SortOrder   int    `json:"sort_order"`
}

type product struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Price       int    `json:"price"`
	Stock       int    `json:"stock"`
}

// All runs every seeder in a single transaction. Either all rows land or none
// do; partial seed state never reaches the live DB.
func All(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("seed begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op if Commit ran

	if err := categories(tx); err != nil {
		return err
	}
	if err := vulnerabilities(tx); err != nil {
		return err
	}
	if err := products(tx); err != nil {
		return err
	}
	if err := users(tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("seed commit: %w", err)
	}
	return nil
}

func categories(tx *sql.Tx) error {
	var rows []category
	if err := json.Unmarshal(categoriesJSON, &rows); err != nil {
		return fmt.Errorf("decode categories.json: %w", err)
	}
	const stmt = `
		INSERT INTO categories (id, name, sort_order)
		VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name       = excluded.name,
			sort_order = excluded.sort_order
	`
	for _, c := range rows {
		if _, err := tx.Exec(stmt, c.ID, c.Name, c.SortOrder); err != nil {
			return fmt.Errorf("seed category %q: %w", c.ID, err)
		}
	}
	return nil
}

func vulnerabilities(tx *sql.Tx) error {
	var rows []vulnerability
	if err := json.Unmarshal(vulnerabilitiesJSON, &rows); err != nil {
		return fmt.Errorf("decode vulnerabilities.json: %w", err)
	}

	// ON CONFLICT(id) DO UPDATE refreshes the descriptive columns from JSON
	// but deliberately omits status/discovered_at/notes so a re-seed never
	// resets crew progress.
	const stmt = `
		INSERT INTO vulnerabilities (id, category_id, title, description, difficulty, sort_order)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			category_id = excluded.category_id,
			title       = excluded.title,
			description = excluded.description,
			difficulty  = excluded.difficulty,
			sort_order  = excluded.sort_order
	`
	for _, v := range rows {
		if v.Difficulty == "" {
			v.Difficulty = "medium"
		}
		if _, err := tx.Exec(stmt, v.ID, v.CategoryID, v.Title, v.Description, v.Difficulty, v.SortOrder); err != nil {
			return fmt.Errorf("seed vuln %q: %w", v.ID, err)
		}
	}
	return nil
}

func users(tx *sql.Tx) error {
	// For each default user: skip if their username already exists. We do
	// NOT update existing rows — once seeded, a password lives only in the
	// DB, so an operator can change it without a code edit and the new
	// value persists across reseeds.
	for _, u := range defaultUsers {
		var existing int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, u.Username).Scan(&existing); err != nil {
			return fmt.Errorf("seed user %q lookup: %w", u.Username, err)
		}
		if existing > 0 {
			continue
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), 12)
		if err != nil {
			return fmt.Errorf("seed user %q hash: %w", u.Username, err)
		}
		admin := 0
		if u.IsAdmin {
			admin = 1
		}
		if _, err := tx.Exec(
			`INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)`,
			u.Username, string(hash), admin,
		); err != nil {
			return fmt.Errorf("seed user %q insert: %w", u.Username, err)
		}
	}
	return nil
}

func products(tx *sql.Tx) error {
	var rows []product
	if err := json.Unmarshal(productsJSON, &rows); err != nil {
		return fmt.Errorf("decode products.json: %w", err)
	}

	const stmt = `
		INSERT OR IGNORE INTO products (slug, name, category, description, price, stock)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	for _, p := range rows {
		if _, err := tx.Exec(stmt, p.Slug, p.Name, p.Category, p.Description, p.Price, p.Stock); err != nil {
			return fmt.Errorf("seed product %q: %w", p.Slug, err)
		}
	}
	return nil
}
