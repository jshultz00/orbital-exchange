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
	"crypto/md5"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Default seeded user accounts. Documented in README. Idempotent: a row is
// only inserted if its username does not already exist, so a password change
// in the DB survives subsequent reseeds.
//
// StationKey is the API access token shown on the crew detail page. Admin's
// key is the prize for the a01-crew-roster-idor → a01-station-key-manifest-dump
// exploit chain. Keys are fixed so fresh databases are deterministic.
var defaultUsers = []struct {
	Username   string
	Password   string
	IsAdmin    bool
	StationKey string
}{
	{Username: "command", Password: "stationcommand", IsAdmin: true, StationKey: "OE-CMD-ce3f9a2b18d4e506fa71"},
	{Username: "ryland", Password: "hailmary42", IsAdmin: false, StationKey: "OE-CRW-4a8b1d7c2e9f3056ab12"},
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
	ID         string `json:"id"`
	CategoryID string `json:"category_id"`
	Title      string `json:"title"`
	Hint       string `json:"hint"`
	Difficulty string `json:"difficulty"`
	SortOrder  int    `json:"sort_order"`
	// IsPlanted gates whether this slot appears on /tracker. Defaults to
	// false (omitted) for roadmap rows; flip to true in JSON when the
	// matching exploit is actually wired into a handler.
	IsPlanted bool `json:"is_planted,omitempty"`
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
	if err := manifests(tx); err != nil {
		return err
	}
	if err := vouchers(tx); err != nil {
		return err
	}
	if err := legacyUsers(tx); err != nil {
		return err
	}
	if err := supplyDrops(tx); err != nil {
		return err
	}
	if err := cargoBundles(tx); err != nil {
		return err
	}
	if err := crewClearances(tx); err != nil {
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

	// ON CONFLICT(id) DO UPDATE refreshes the static columns from JSON
	// but deliberately omits status/discovered_at/notes so a re-seed never
	// resets crew progress. is_planted IS refreshed from JSON: it's a code-
	// level fact (does the exploit exist?), not crew progress.
	const stmt = `
		INSERT INTO vulnerabilities (id, category_id, title, hint, difficulty, sort_order, is_planted)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			category_id = excluded.category_id,
			title       = excluded.title,
			hint        = excluded.hint,
			difficulty  = excluded.difficulty,
			sort_order  = excluded.sort_order,
			is_planted  = excluded.is_planted
	`
	for _, v := range rows {
		if v.Difficulty == "" {
			v.Difficulty = "medium"
		}
		planted := 0
		if v.IsPlanted {
			planted = 1
		}
		if _, err := tx.Exec(stmt, v.ID, v.CategoryID, v.Title, v.Hint, v.Difficulty, v.SortOrder, planted); err != nil {
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
	//
	// Exception: station_key is backfilled for existing rows that have the
	// empty-string default (left by the ALTER TABLE migration). This keeps
	// the exploit chain functional on databases created before the column
	// was added.
	for _, u := range defaultUsers {
		if _, err := tx.Exec(
			`UPDATE users SET station_key = ? WHERE username = ? AND station_key = ''`,
			u.StationKey, u.Username,
		); err != nil {
			return fmt.Errorf("seed user %q station_key backfill: %w", u.Username, err)
		}
	}
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
			`INSERT INTO users (username, password_hash, is_admin, station_key) VALUES (?, ?, ?, ?)`,
			u.Username, string(hash), admin, u.StationKey,
		); err != nil {
			return fmt.Errorf("seed user %q insert: %w", u.Username, err)
		}
	}
	return nil
}

// defaultManifests are seeded once per user. Idempotent: if the user already
// has any manifest row we skip seeding theirs entirely, so manifests created
// at runtime aren't disturbed and the seed values don't keep duplicating on
// reboot.
//
// Planted vuln a01-airlock-manifest-override depends on these rows existing:
// crew see their own at /manifest, can guess sequential IDs, and pull
// someone else's via /manifest/{id} because the lookup ignores ownership.
var defaultManifests = []struct {
	Username     string
	Summary      string
	ItemsJSON    string
	TotalCredits int
}{
	{
		Username:     "command",
		Summary:      "Cycle 411 // Station Command ration draw",
		ItemsJSON:    `[{"name":"Bridge ration pack","qty":4,"unit_price":85},{"name":"Stim coffee, dark","qty":2,"unit_price":40}]`,
		TotalCredits: 420,
	},
	{
		Username:     "command",
		Summary:      "Cycle 412 // Engineering supply pull",
		ItemsJSON:    `[{"name":"Salvage cell, charged","qty":3,"unit_price":210},{"name":"Hull patch tape","qty":5,"unit_price":35}]`,
		TotalCredits: 805,
	},
	{
		Username:     "ryland",
		Summary:      "Cycle 412 // Crew ration draw",
		ItemsJSON:    `[{"name":"Standard ration pack","qty":7,"unit_price":55},{"name":"Oxygen canister, half","qty":1,"unit_price":120}]`,
		TotalCredits: 505,
	},
}

func manifests(tx *sql.Tx) error {
	for _, m := range defaultManifests {
		var userID int64
		err := tx.QueryRow(`SELECT id FROM users WHERE username = ?`, m.Username).Scan(&userID)
		if err != nil {
			return fmt.Errorf("seed manifest lookup user %q: %w", m.Username, err)
		}

		var existing int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM manifests WHERE user_id = ? AND summary = ?`, userID, m.Summary).Scan(&existing); err != nil {
			return fmt.Errorf("seed manifest count %q: %w", m.Summary, err)
		}
		if existing > 0 {
			continue
		}

		if _, err := tx.Exec(
			`INSERT INTO manifests (user_id, summary, items_json, total_credits) VALUES (?, ?, ?, ?)`,
			userID, m.Summary, m.ItemsJSON, m.TotalCredits,
		); err != nil {
			return fmt.Errorf("seed manifest insert %q: %w", m.Summary, err)
		}
	}
	return nil
}

// defaultVouchers seeds a small set of ration discount codes. Each carries a
// flat credit discount. The redemption flow at POST /cart/voucher validates
// codes but does not mark them spent — planted vuln a06-promo-code-replay.
var defaultVouchers = []struct {
	Code        string
	Discount    int
	Description string
}{
	{Code: "RATION10", Discount: 10, Description: "10cr off — cycle 412 morale push"},
	{Code: "SALVAGE25", Discount: 25, Description: "25cr off — salvage program kickback"},
}

// defaultLegacyUsers seeds the decommissioned-crew archive. Hashes are
// computed at seed time from these plaintexts so the file remains readable
// and the crackable answers are explicit. PLANTED VULN a04-weak-password-hash:
// raw unsalted MD5, by design.
var defaultLegacyUsers = []struct {
	Username string
	Password string
	Role     string
}{
	{Username: "h.vance", Password: "orion", Role: "navigation"},
	{Username: "k.osei", Password: "letmein", Role: "hydroponics"},
	{Username: "t.mori", Password: "comet1995", Role: "engineering"},
}

func legacyUsers(tx *sql.Tx) error {
	const stmt = `
		INSERT OR IGNORE INTO legacy_users (username, md5_hash, role)
		VALUES (?, ?, ?)
	`
	for _, u := range defaultLegacyUsers {
		sum := md5.Sum([]byte(u.Password))
		if _, err := tx.Exec(stmt, u.Username, hex.EncodeToString(sum[:]), u.Role); err != nil {
			return fmt.Errorf("seed legacy user %q: %w", u.Username, err)
		}
	}
	return nil
}

// defaultSupplyDrops seeds an active limited-capacity ration drop used by the
// planted vuln a06-allocation-race. Capacity is intentionally small so the
// race window matters: a single crew member firing concurrent claim POSTs can
// pass the read-then-write gate more than once.
var defaultSupplyDrops = []struct {
	Slug        string
	Name        string
	Description string
	Capacity    int
}{
	{
		Slug:        "cycle-412-ration-drop",
		Name:        "Cycle 412 // Emergency ration drop",
		Description: "Limited-run ration allocation. One pack per crew member while the drop is open.",
		Capacity:    3,
	},
}

func supplyDrops(tx *sql.Tx) error {
	const stmt = `
		INSERT OR IGNORE INTO supply_drops (slug, name, description, capacity, remaining, active)
		VALUES (?, ?, ?, ?, ?, 1)
	`
	for _, d := range defaultSupplyDrops {
		if _, err := tx.Exec(stmt, d.Slug, d.Name, d.Description, d.Capacity, d.Capacity); err != nil {
			return fmt.Errorf("seed supply drop %q: %w", d.Slug, err)
		}
	}
	return nil
}

func vouchers(tx *sql.Tx) error {
	const stmt = `
		INSERT OR IGNORE INTO vouchers (code, discount, description)
		VALUES (?, ?, ?)
	`
	for _, v := range defaultVouchers {
		if _, err := tx.Exec(stmt, v.Code, v.Discount, v.Description); err != nil {
			return fmt.Errorf("seed voucher %q: %w", v.Code, err)
		}
	}
	return nil
}

// defaultCargoBundles seeds one active bundle for the partial-rollback planted
// vuln. Capacity is small (3) so the race to exhaustion is quick — a few
// claims drain remaining to 0, then the next claim triggers the CHECK
// constraint failure that leaves the manifest persisted but remaining unchanged.
var defaultCargoBundles = []struct {
	Slug        string
	Name        string
	Description string
	Capacity    int
}{
	{
		Slug:        "cycle-412-emergency-bundle",
		Name:        "Cycle 412 // Emergency Cargo Bundle",
		Description: "Limited emergency allocation. Claim while supplies last — one bundle per transaction.",
		Capacity:    3,
	},
}

func cargoBundles(tx *sql.Tx) error {
	const stmt = `
		INSERT OR IGNORE INTO cargo_bundles (slug, name, description, remaining, active)
		VALUES (?, ?, ?, ?, 1)
	`
	for _, b := range defaultCargoBundles {
		if _, err := tx.Exec(stmt, b.Slug, b.Name, b.Description, b.Capacity); err != nil {
			return fmt.Errorf("seed cargo bundle %q: %w", b.Slug, err)
		}
	}
	return nil
}

// crewClearances seeds a clearance token for the "ryland" crew member.
// It's used by the planted fail-open vuln: a valid token proves the normal
// (ErrNoRows) denial path works, while a crafted token with a quote character
// triggers the error path that falls through instead of denying.
func crewClearances(tx *sql.Tx) error {
	var rylandID int64
	err := tx.QueryRow(`SELECT id FROM users WHERE username = 'ryland'`).Scan(&rylandID)
	if err != nil {
		// ryland may not exist on this database yet; skip rather than fail.
		return nil
	}
	const stmt = `
		INSERT OR IGNORE INTO crew_clearances (token, user_id, granted_by)
		VALUES (?, ?, 'command')
	`
	if _, err := tx.Exec(stmt, "OE-CLR-ryland-cycle412", rylandID); err != nil {
		return fmt.Errorf("seed crew clearance: %w", err)
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
