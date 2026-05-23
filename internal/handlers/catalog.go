// Package handlers contains the HTTP handlers for Orbital Exchange.
// Each route group lives in its own file (catalog.go, auth.go, etc.) and
// is wired into the mux in cmd/server/main.go.
package handlers

import (
	"database/sql"
	"errors"
	"log"
	"net/http"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

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

// List renders /catalog — every product, grouped by category.
func (c *Catalog) List(w http.ResponseWriter, r *http.Request) {
	const q = `
		SELECT id, slug, name, category, description, price, stock
		FROM products
		ORDER BY category, name
	`
	rows, err := c.DB.Query(q)
	if err != nil {
		log.Printf("catalog list query: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

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
