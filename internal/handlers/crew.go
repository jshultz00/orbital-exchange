package handlers

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Crew serves individual crew member roster entries.
//
// Planted vuln a01-crew-roster-idor: the Detail handler looks up crew by ID
// alone, with no check that the crew member is the session user. Any logged-in
// crew member can guess sequential IDs and read another crew member's entry.
// The IDOR detection flips the tracker row when the viewer is not the crew
// member whose record is fetched.
type Crew struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const crewIDORTrackerID = "a01-crew-roster-idor"

// CrewDetail is the full crew member record for the detail view.
// StationKey is the API token used to authenticate against /manifest/export.
// Showing it here without an ownership check is the planted IDOR surface.
type CrewDetail struct {
	ID         int64
	Username   string
	IsAdmin    bool
	StationKey string
	CreatedAt  string
}

// Index renders /crew. Admins see the full roster; regular crew see only
// their own entry. The legitimate UI never exposes other crew IDs to a
// non-admin viewer — but /crew/{id} has no ownership check, so anyone can
// still read any record by guessing sequential IDs directly. That gap is
// the planted IDOR (a01-crew-roster-idor).
func (c *Crew) Index(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}

	q := `
		SELECT id, username, is_admin = 1,
		       strftime('%Y-%m-%d %H:%M', created_at)
		FROM users
		ORDER BY id ASC
	`
	args := []any{}
	if !user.IsAdmin {
		q = `
			SELECT id, username, is_admin = 1,
			       strftime('%Y-%m-%d %H:%M', created_at)
			FROM users
			WHERE id = ?
		`
		args = append(args, user.ID)
	}
	rows, err := c.DB.Query(q, args...)
	if err != nil {
		log.Printf("crew index: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var roster []CrewRow
	for rows.Next() {
		var row CrewRow
		if err := rows.Scan(&row.ID, &row.Username, &row.IsAdmin, &row.CreatedAt); err != nil {
			log.Printf("crew index scan: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		roster = append(roster, row)
	}

	data := pageData(r, c.Session, "Crew Roster")
	data["Roster"] = roster
	render(w, c.Views, "crew_index", data)
}

// Detail renders /crew/{id}. PLANTED VULN: this handler does not verify
// that the crew member's id matches the session — any logged-in crew member
// can pull any crew member's record by ID.
func (c *Crew) Detail(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}

	const q = `
		SELECT id, username, is_admin = 1, station_key,
		       strftime('%Y-%m-%d %H:%M', created_at)
		FROM users
		WHERE id = ?
	`
	var detail CrewDetail
	err = c.DB.QueryRow(q, id).Scan(
		&detail.ID, &detail.Username, &detail.IsAdmin, &detail.StationKey, &detail.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("crew detail %d: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// IDOR detection: flip the tracker when a regular (non-admin) crew member
	// views someone else's record. Admins legitimately browse the roster, so
	// their access doesn't count as exploitation.
	if detail.ID != user.ID && !user.IsAdmin {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := c.DB.Exec(flip, crewIDORTrackerID); err != nil {
			log.Printf("crew IDOR discover flip: %v", err)
		}
	}

	data := pageData(r, c.Session, "Crew Member "+detail.Username)
	data["Crew"] = detail
	data["IsOwn"] = detail.ID == user.ID
	render(w, c.Views, "crew_detail", data)
}
