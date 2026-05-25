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

// Command renders the Station Command admin dashboard.
//
// Defensive baseline: requireAdmin gates every handler in this group, so
// non-admins get a 403 and anonymous users are sent to /login. Future
// A01 planted vulns (e.g. a01-crew-roster-idor) live downstream of this
// page; the gate is the layer they will break.
type Command struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// CommandStats captures dashboard counters in one query trip.
type CommandStats struct {
	Users        int
	Products     int
	CartItems    int
	CommsEntries int
	Vulns        int
	VulnsDone    int
}

// CrewRow is one row of the crew roster table.
type CrewRow struct {
	ID        int64
	Username  string
	IsAdmin   bool
	CreatedAt string
	AvatarURL string
}

// Dashboard renders /command — placeholder Station Command home.
// Planted A05 (default credentials): on first access by an admin, the
// tracker row for "a02-default-station-credentials" flips to discovered.
func (c *Command) Dashboard(w http.ResponseWriter, r *http.Request) {
	user := requireAdmin(w, r, c.Session)
	if user == nil {
		return
	}

	// Flip the tracker row when an admin user accesses the command dashboard
	// for the first time. Idempotent: the status guard only matches undiscovered.
	const flip = `
		UPDATE vulnerabilities
		SET status = 'discovered',
		    discovered_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'undiscovered'
	`
	if _, err := c.DB.Exec(flip, "a02-default-station-credentials"); err != nil {
		log.Printf("command dashboard discover flip: %v", err)
	}

	stats, err := c.loadStats()
	if err != nil {
		log.Printf("command stats: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	roster, err := c.loadRoster()
	if err != nil {
		log.Printf("command roster: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := pageData(r, c.Session, "Station Command")
	data["Stats"] = stats
	data["Roster"] = roster
	render(w, c.Views, "command", data)
}

func (c *Command) loadStats() (CommandStats, error) {
	var s CommandStats
	const q = `
		SELECT
			(SELECT COUNT(*) FROM users),
			(SELECT COUNT(*) FROM products),
			(SELECT COUNT(*) FROM cart_items),
			(SELECT COUNT(*) FROM comms_entries),
			(SELECT COUNT(*) FROM vulnerabilities),
			(SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('discovered','exploited'))
	`
	err := c.DB.QueryRow(q).Scan(&s.Users, &s.Products, &s.CartItems, &s.CommsEntries, &s.Vulns, &s.VulnsDone)
	return s, err
}

// ToggleAdmin grants or revokes admin status for a crew member.
//
// PLANTED VULN a09-no-audit-on-privileged-action: this handler promotes or
// demotes a crew member but writes no audit record — no DB row, no log line.
// The change takes effect silently; an investigator looking for evidence of who
// did what will find nothing.
func (c *Command) ToggleAdmin(w http.ResponseWriter, r *http.Request) {
	user := requireAdmin(w, r, c.Session)
	if user == nil {
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	var current int
	err = c.DB.QueryRow(`SELECT is_admin FROM users WHERE id = ?`, id).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("toggle admin lookup %d: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	newVal := 1
	if current == 1 {
		newVal = 0
	}

	// VULNERABLE BY DESIGN: no audit log is written here. The role change
	// happens, but there is no record of who performed it or when.
	if _, err := c.DB.Exec(`UPDATE users SET is_admin = ? WHERE id = ?`, newVal, id); err != nil {
		log.Printf("toggle admin update %d: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Flip the tracker the first time any privileged action completes with no
	// audit trail. Detection is on the action itself — the absence of a log
	// entry is the planted lesson.
	const flip = `
		UPDATE vulnerabilities
		SET status = 'discovered',
		    discovered_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'undiscovered'
	`
	if _, err := c.DB.Exec(flip, "a09-no-audit-on-privileged-action"); err != nil {
		log.Printf("toggle admin tracker flip: %v", err)
	}

	http.Redirect(w, r, "/command", http.StatusSeeOther)
}

func (c *Command) loadRoster() ([]CrewRow, error) {
	const q = `
		SELECT id, username, is_admin = 1, strftime('%Y-%m-%d', created_at)
		FROM users
		ORDER BY id
	`
	rows, err := c.DB.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roster []CrewRow
	for rows.Next() {
		var r CrewRow
		if err := rows.Scan(&r.ID, &r.Username, &r.IsAdmin, &r.CreatedAt); err != nil {
			return nil, err
		}
		roster = append(roster, r)
	}
	return roster, rows.Err()
}
