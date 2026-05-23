package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Manifest serves crew supply manifests — read-only requisition receipts.
//
// Planted vuln a01-airlock-manifest-override: the Detail handler looks up
// rows by id alone, with no check that the manifest's user_id matches the
// session. Crew can guess sequential IDs and read another crew member's
// manifest. The IDOR detection flips the tracker row when the viewer's
// session user does not own the manifest they just fetched.
type Manifest struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const manifestIDORTrackerID = "a01-airlock-manifest-override"

// ManifestRow is one row of the manifest index — only fields needed for the list view.
type ManifestRow struct {
	ID           int64
	Summary      string
	TotalCredits int
	CreatedAt    string
}

// ManifestDetail is the parsed full manifest for the detail view.
type ManifestDetail struct {
	ID           int64
	OwnerID      int64
	OwnerName    string
	Summary      string
	Items        []ManifestItem
	TotalCredits int
	CreatedAt    string
}

// ManifestItem mirrors the JSON object stored in manifests.items_json.
// Subtotal is computed at decode time so templates stay arithmetic-free.
type ManifestItem struct {
	Name      string `json:"name"`
	Qty       int    `json:"qty"`
	UnitPrice int    `json:"unit_price"`
	Subtotal  int    `json:"-"`
}

// Index renders /manifest — the current user's own manifests.
// This is the discoverable surface: it shows the crew member their IDs, which
// hints that other IDs (belonging to other crew) might exist nearby.
func (m *Manifest) Index(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, m.Session)
	if user == nil {
		return
	}

	const q = `
		SELECT id, summary, total_credits,
		       strftime('%Y-%m-%d %H:%M', created_at)
		FROM manifests
		WHERE user_id = ?
		ORDER BY id DESC
	`
	rows, err := m.DB.Query(q, user.ID)
	if err != nil {
		log.Printf("manifest index: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []ManifestRow
	for rows.Next() {
		var row ManifestRow
		if err := rows.Scan(&row.ID, &row.Summary, &row.TotalCredits, &row.CreatedAt); err != nil {
			log.Printf("manifest index scan: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		list = append(list, row)
	}

	data := pageData(r, m.Session, "Manifest")
	data["Manifests"] = list
	render(w, m.Views, "manifest_index", data)
}

// Detail renders /manifest/{id}. PLANTED VULN: this handler does not verify
// that the manifest's user_id matches the session — any logged-in crew member
// can pull any manifest by ID.
func (m *Manifest) Detail(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, m.Session)
	if user == nil {
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}

	const q = `
		SELECT m.id, m.user_id, u.username, m.summary, m.items_json, m.total_credits,
		       strftime('%Y-%m-%d %H:%M', m.created_at)
		FROM manifests m
		JOIN users u ON u.id = m.user_id
		WHERE m.id = ?
	`
	var (
		detail   ManifestDetail
		itemsRaw string
	)
	err = m.DB.QueryRow(q, id).Scan(
		&detail.ID, &detail.OwnerID, &detail.OwnerName, &detail.Summary,
		&itemsRaw, &detail.TotalCredits, &detail.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("manifest detail %d: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := json.Unmarshal([]byte(itemsRaw), &detail.Items); err != nil {
		log.Printf("manifest detail %d items decode: %v", id, err)
	}
	for i := range detail.Items {
		detail.Items[i].Subtotal = detail.Items[i].Qty * detail.Items[i].UnitPrice
	}

	// IDOR detection: if the viewer is NOT the manifest owner, flip the
	// tracker row. Idempotent — the UPDATE guard only matches undiscovered.
	if detail.OwnerID != user.ID {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := m.DB.Exec(flip, manifestIDORTrackerID); err != nil {
			log.Printf("manifest IDOR discover flip: %v", err)
		}
	}

	data := pageData(r, m.Session, "Manifest #"+strconv.FormatInt(id, 10))
	data["Manifest"] = detail
	data["IsOwner"] = detail.OwnerID == user.ID
	render(w, m.Views, "manifest_detail", data)
}
