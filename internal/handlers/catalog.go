// Package handlers contains the HTTP handlers for Orbital Exchange.
// Each route group lives in its own file (catalog.go, auth.go, etc.) and
// is wired into the mux in cmd/server/main.go.
package handlers

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// requisitionSearchTrackerID is the planted A03 (Injection) row flipped when
// the catalog search query contains classic SQL-injection markers. The search
// box concatenates raw input into the WHERE clause by design.
const requisitionSearchTrackerID = "a03-requisition-search-sqli"

// Catalog handles browsing the commissary inventory.
//
// Dependencies (DB, Views, Session) are passed at construction so handlers
// stay independent of process-global state and easy to test.
type Catalog struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// Product mirrors a row in the products table for view rendering.
type Product struct {
	ID          int64
	Slug        string
	Name        string
	Category    string // raw slug from DB (e.g. "ration")
	Description string
	Price       int
	Stock       int
}

// CategorySection groups products by category for the listing page.
// Display order is defined in catalogCategoryOrder below.
type CategorySection struct {
	Slug     string // "ration"
	Title    string // "Rations"
	Products []Product
}

// catalogCategoryOrder pins the visual order of category sections and maps
// raw category slugs to human display titles. Unknown categories fall back
// to a title-cased slug and appear at the bottom.
var catalogCategoryOrder = []struct {
	Slug, Title string
}{
	{"ration", "Rations"},
	{"oxygen", "Oxygen Reserves"},
	{"medical", "Medical"},
	{"consumable", "Consumables"},
	{"tool", "Tools"},
	{"salvage", "Salvage"},
}

// List renders /catalog — every product, grouped by category. Accepts an
// optional ?q= search term which is concatenated directly into the WHERE
// clause (planted A03 injection vuln: requisitionSearchTrackerID).
func (c *Catalog) List(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("q"))

	query := `
		SELECT id, slug, name, category, description, price, stock
		FROM products
		ORDER BY category, name
	`
	if search != "" {
		// VULNERABLE BY DESIGN: raw user input is interpolated into the SQL
		// string instead of bound as a parameter. Classic UNION / OR 1=1
		// payloads work against this. Do not "fix" — see CLAUDE.md.
		query = `
			SELECT id, slug, name, category, description, price, stock
			FROM products
			WHERE name LIKE '%` + search + `%' OR description LIKE '%` + search + `%'
			ORDER BY category, name
		`
	}

	rows, err := c.DB.Query(query)
	if err != nil {
		// Surface the SQL error to the page so injection feedback is
		// usable (mirrors classic vulnerable apps that echo DB errors).
		log.Printf("catalog list query: %v (q=%q)", err, search)
		c.renderSearchError(w, r, search, err)
		return
	}
	defer rows.Close()

	if search != "" && looksLikeSQLi(search) {
		c.flipSearchDiscovery()
	}

	byCategory := make(map[string][]Product)
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.Category, &p.Description, &p.Price, &p.Stock); err != nil {
			log.Printf("catalog list scan: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		byCategory[p.Category] = append(byCategory[p.Category], p)
	}
	if err := rows.Err(); err != nil {
		log.Printf("catalog list rows: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Build sections in pinned order; tuck any unrecognized categories at the end.
	seen := make(map[string]bool, len(catalogCategoryOrder))
	sections := make([]CategorySection, 0, len(byCategory))
	for _, cat := range catalogCategoryOrder {
		if products, ok := byCategory[cat.Slug]; ok {
			sections = append(sections, CategorySection{Slug: cat.Slug, Title: cat.Title, Products: products})
			seen[cat.Slug] = true
		}
	}
	for slug, products := range byCategory {
		if !seen[slug] {
			sections = append(sections, CategorySection{Slug: slug, Title: slug, Products: products})
		}
	}

	data := pageData(r, c.Session, "Catalog")
	data["Sections"] = sections
	data["SearchQuery"] = search
	render(w, c.Views, "catalog", data)
}

// looksLikeSQLi flags classic injection markers in the search input. Used to
// decide when to flip the planted A03 tracker row.
func looksLikeSQLi(s string) bool {
	lower := strings.ToLower(s)
	markers := []string{"' or ", "\" or ", "union select", "--", "' --", "/*", "' )", "or 1=1", "or '1'='1"}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

func (c *Catalog) flipSearchDiscovery() {
	const flip = `
		UPDATE vulnerabilities
		SET status = 'discovered',
		    discovered_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'undiscovered'
	`
	if _, err := c.DB.Exec(flip, requisitionSearchTrackerID); err != nil {
		log.Printf("requisition search discover flip: %v", err)
	}
}

// renderSearchError echoes a SQL parse/exec error back to the catalog page so
// injection probes get useful feedback. Also flips the planted tracker row
// when the failing query carries injection markers — failed UNIONs still
// prove the surface exists.
func (c *Catalog) renderSearchError(w http.ResponseWriter, r *http.Request, search string, dbErr error) {
	if looksLikeSQLi(search) {
		c.flipSearchDiscovery()
	}
	data := pageData(r, c.Session, "Catalog")
	data["Sections"] = []CategorySection{}
	data["SearchQuery"] = search
	data["SearchError"] = dbErr.Error()
	render(w, c.Views, "catalog", data)
}

// Detail renders /catalog/{slug} — a single product page.
// 404s if the slug doesn't resolve.
func (c *Catalog) Detail(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	const q = `
		SELECT id, slug, name, category, description, price, stock
		FROM products
		WHERE slug = ?
	`
	var p Product
	err := c.DB.QueryRow(q, slug).Scan(&p.ID, &p.Slug, &p.Name, &p.Category, &p.Description, &p.Price, &p.Stock)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("catalog detail %q: %v", slug, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := pageData(r, c.Session, p.Name)
	data["Product"] = p
	render(w, c.Views, "product", data)
}

// render is a small helper used by every handler in this package: write the
// HTML content-type, ask views to render the named page, and log + 500 on
// failure. Keeping it in handlers (not views) lets us tailor error handling
// to HTTP semantics here.
func render(w http.ResponseWriter, v *views.Views, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := v.Render(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
