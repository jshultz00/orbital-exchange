package handlers

import (
	"database/sql"
	"log"
	"net/http"

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
	Users         int
	Products      int
	CartItems     int
	CommsEntries  int
	Vulns         int
	VulnsDone     int
}

// CrewRow is one row of the crew roster table.
type CrewRow struct {
	ID        int64
	Username  string
	IsAdmin   bool
	CreatedAt string
}

// Dashboard renders /command — placeholder Station Command home.
func (c *Command) Dashboard(w http.ResponseWriter, r *http.Request) {
	user := requireAdmin(w, r, c.Session)
	if user == nil {
		return
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
