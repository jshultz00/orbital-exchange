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

const stationKeyExfilTrackerID = "a01-station-key-manifest-dump"

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

// exportRow is a single manifest record in the JSON export payload.
type exportRow struct {
	ID           int64  `json:"id"`
	Owner        string `json:"owner"`
	Summary      string `json:"summary"`
	TotalCredits int    `json:"total_credits"`
	CreatedAt    string `json:"created_at"`
}

// Export serves GET /manifest/export?key=<station_key> — a token-authenticated
// API endpoint that returns manifests as JSON.
//
// Planted vuln a01-station-key-manifest-dump: the endpoint scopes results to
// the key owner's manifests for regular crew, but an admin key returns ALL
// manifests with no further check. An attacker who obtained the admin station
// key via the crew roster IDOR can dump the full ledger here.
func (m *Manifest) Export(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, `{"error":"station key required — supply ?key=<your-station-key>"}`, http.StatusUnauthorized)
		return
	}

	// Resolve the key to a user row.
	var (
		ownerID   int64
		ownerName string
		isAdmin   bool
	)
	err := m.DB.QueryRow(
		`SELECT id, username, is_admin = 1 FROM users WHERE station_key = ?`, key,
	).Scan(&ownerID, &ownerName, &isAdmin)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, `{"error":"invalid station key"}`, http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("manifest export key lookup: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Admin key: dump all manifests. Regular key: own manifests only.
	var (
		rows *sql.Rows
		q    string
	)
	if isAdmin {
		q = `
			SELECT m.id, u.username, m.summary, m.total_credits,
			       strftime('%Y-%m-%d %H:%M', m.created_at)
			FROM manifests m
			JOIN users u ON u.id = m.user_id
			ORDER BY m.id ASC
		`
		rows, err = m.DB.Query(q)
	} else {
		q = `
			SELECT m.id, u.username, m.summary, m.total_credits,
			       strftime('%Y-%m-%d %H:%M', m.created_at)
			FROM manifests m
			JOIN users u ON u.id = m.user_id
			WHERE m.user_id = ?
			ORDER BY m.id ASC
		`
		rows, err = m.DB.Query(q, ownerID)
	}
	if err != nil {
		log.Printf("manifest export query: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var records []exportRow
	for rows.Next() {
		var rec exportRow
		if err := rows.Scan(&rec.ID, &rec.Owner, &rec.Summary, &rec.TotalCredits, &rec.CreatedAt); err != nil {
			log.Printf("manifest export scan: %v", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		records = append(records, rec)
	}

	// Detection: flip the tracker when an admin key returns multi-owner data,
	// meaning someone is using a stolen key to exfiltrate the full ledger.
	if isAdmin && len(records) > 0 {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := m.DB.Exec(flip, stationKeyExfilTrackerID); err != nil {
			log.Printf("manifest export tracker flip: %v", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(records); err != nil {
		log.Printf("manifest export encode: %v", err)
	}
}
