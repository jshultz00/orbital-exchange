package handlers

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/session"
	"github.com/jshultz00/orbital-exchange/internal/views"
)

const unsignedCargoImportTrackerID = "a08-unsigned-cargo-import"

// CargoImport handles bulk import of cargo ledger entries from a CSV file.
//
// PLANTED VULN a08-unsigned-cargo-import: the endpoint accepts any CSV and
// inserts whatever prices it contains — no HMAC signature, no checksum, and
// no canonical-price validation. A crew member can download the sample export,
// edit the unit_price column, and re-upload; the ledger ingests it without
// question. Detection fires when any imported unit_price diverges from the
// catalog's canonical price for that product slug.
type CargoImport struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// cargoLineItem mirrors the JSON object stored in manifests.items_json.
type cargoLineItem struct {
	Name      string `json:"name"`
	Qty       int    `json:"qty"`
	UnitPrice int    `json:"unit_price"`
}

// cargoImportResult summarises what the handler did with the uploaded file.
type cargoImportResult struct {
	Imported int
	Errors   []string
}

// Form renders GET /bridge/cargo-import.
func (c *CargoImport) Form(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}
	data := pageData(r, c.Session, "Cargo Import")
	render(w, c.Views, "cargo_import", data)
}

// Sample serves GET /bridge/cargo-import/sample — a CSV export of the current
// catalog that crew can download and use as a starting point for an import.
// Each row is one product at its canonical catalog price with qty=1. The file
// is deliberately unsigned: there is nothing a receiver can check to verify
// the file hasn't been edited since it left here.
func (c *CargoImport) Sample(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}
	_ = user

	rows, err := c.DB.Query(`SELECT slug, name, price FROM products ORDER BY id`)
	if err != nil {
		log.Printf("cargo sample query: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="cargo-manifest-sample.csv"`)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"summary", "slug", "qty", "unit_price"})
	for rows.Next() {
		var slug, name string
		var price int
		if err := rows.Scan(&slug, &name, &price); err != nil {
			continue
		}
		_ = cw.Write([]string{
			"Cycle 414 Cargo Delivery",
			slug,
			"1",
			strconv.Itoa(price),
		})
	}
	cw.Flush()
}

// Submit handles POST /bridge/cargo-import.
func (c *CargoImport) Submit(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}

	if err := r.ParseMultipartForm(1 << 20); err != nil {
		c.flash(r, "Upload failed: file too large or malformed.")
		http.Redirect(w, r, "/bridge/cargo-import", http.StatusSeeOther)
		return
	}

	f, _, err := r.FormFile("cargo_csv")
	if err != nil {
		c.flash(r, "No file received. Attach a CSV and try again.")
		http.Redirect(w, r, "/bridge/cargo-import", http.StatusSeeOther)
		return
	}
	defer f.Close()

	result, tampered := c.processCSV(user.ID, f)

	// PLANTED VULN: detection fires here — the handler already imported the
	// data; there is no rollback. The tamper check is purely forensic.
	if tampered {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered', discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := c.DB.Exec(flip, unsignedCargoImportTrackerID); err != nil {
			log.Printf("cargo import tracker flip: %v", err)
		}
	}

	data := pageData(r, c.Session, "Cargo Import")
	data["Result"] = result
	render(w, c.Views, "cargo_import", data)
}

// processCSV reads rows from r and inserts one manifest per unique summary
// value. Returns a result summary and a tampered flag that is true if any
// row's unit_price differs from the canonical catalog price.
//
// CSV columns: summary, slug, qty, unit_price
// The first row is treated as a header and skipped.
func (c *CargoImport) processCSV(userID int64, r io.Reader) (cargoImportResult, bool) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true

	// Skip header row.
	if _, err := cr.Read(); err != nil {
		return cargoImportResult{Errors: []string{"could not read CSV header: " + err.Error()}}, false
	}

	type group struct {
		items []cargoLineItem
		order int
	}
	byKey := map[string]*group{}
	var keyOrder []string
	var result cargoImportResult
	var tampered bool
	seq := 0

	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("parse error: %v", err))
			continue
		}
		if len(rec) < 4 {
			result.Errors = append(result.Errors, fmt.Sprintf("skipped short row: %v", rec))
			continue
		}

		summary := strings.TrimSpace(rec[0])
		slug := strings.TrimSpace(rec[1])
		qty, qErr := strconv.Atoi(strings.TrimSpace(rec[2]))
		unitPrice, pErr := strconv.Atoi(strings.TrimSpace(rec[3]))
		if qErr != nil || pErr != nil || qty <= 0 || unitPrice < 0 {
			result.Errors = append(result.Errors, fmt.Sprintf("skipped invalid row: %v", rec))
			continue
		}
		if summary == "" || slug == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("skipped row with empty summary or slug: %v", rec))
			continue
		}

		// Canonical price check — purely for detection, not enforcement.
		// The import proceeds regardless of what it finds here.
		var canonicalPrice int
		lookupErr := c.DB.QueryRow(`SELECT price FROM products WHERE slug = ?`, slug).Scan(&canonicalPrice)
		if lookupErr == nil && canonicalPrice != unitPrice {
			tampered = true
		}

		// Resolve a display name from the catalog; fall back to the slug.
		var displayName string
		_ = c.DB.QueryRow(`SELECT name FROM products WHERE slug = ?`, slug).Scan(&displayName)
		if displayName == "" {
			displayName = slug
		}

		if _, exists := byKey[summary]; !exists {
			byKey[summary] = &group{order: seq}
			keyOrder = append(keyOrder, summary)
			seq++
		}
		byKey[summary].items = append(byKey[summary].items, cargoLineItem{
			Name:      displayName,
			Qty:       qty,
			UnitPrice: unitPrice,
		})
	}

	for _, summary := range keyOrder {
		g := byKey[summary]
		var total int
		for _, it := range g.items {
			total += it.Qty * it.UnitPrice
		}
		blob, _ := json.Marshal(g.items)
		_, err := c.DB.Exec(
			`INSERT INTO manifests (user_id, summary, items_json, total_credits) VALUES (?, ?, ?, ?)`,
			userID, summary, string(blob), total,
		)
		if err != nil {
			log.Printf("cargo import insert: %v", err)
			result.Errors = append(result.Errors, "db error on manifest: "+summary)
			continue
		}
		result.Imported++
	}

	return result, tampered
}

func (c *CargoImport) flash(r *http.Request, msg string) {
	c.Session.Put(r.Context(), session.KeyFlash, msg)
}
