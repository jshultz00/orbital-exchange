package handlers

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Comms handles the station comms log — a public feedback / message board.
// Anonymous submissions are allowed by design; the comms log is the planned
// home of several A03 (XSS, log-injection) planted vulns.
//
// Defensive baseline:
//   - html/template auto-escapes user input on render.
//   - Body and author lengths bounded.
//   - user_id populated from session when authed, NULL otherwise.
type Comms struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// CommsEntry is one row of the comms log for rendering.
type CommsEntry struct {
	ID        int64
	Author    string
	Body      template.HTML // PLANTED VULN a03-comms-stored-xss: rendered unescaped
	CreatedAt string        // pre-formatted in SQL for simplicity
	FromCrew  bool          // true if user_id is non-NULL — UI styles authed entries
}

// List renders /comms.
func (c *Comms) List(w http.ResponseWriter, r *http.Request) {
	const q = `
		SELECT id, author, body,
		       strftime('%Y-%m-%d %H:%M', created_at) AS created_at,
		       user_id IS NOT NULL AS from_crew
		FROM comms_entries
		ORDER BY created_at DESC
		LIMIT 100
	`
	rows, err := c.DB.Query(q)
	if err != nil {
		log.Printf("comms list query: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var entries []CommsEntry
	for rows.Next() {
		var e CommsEntry
		var bodyStr string
		if err := rows.Scan(&e.ID, &e.Author, &bodyStr, &e.CreatedAt, &e.FromCrew); err != nil {
			log.Printf("comms list scan: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		e.Body = template.HTML(bodyStr) // PLANTED VULN: no escaping
		entries = append(entries, e)
	}

	data := pageData(r, c.Session, "Comms Log")
	data["Entries"] = entries
	render(w, c.Views, "comms", data)
}

// Submit appends a new comms entry. Both anonymous and authed crew may post.
func (c *Comms) Submit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	body := trimMax(r.PostFormValue("body"), 2000)
	if body == "" {
		http.Redirect(w, r, "/comms", http.StatusSeeOther)
		return
	}

	user := currentUser(r, c.Session)

	// Author: prefer authed username, fall back to submitted name, then "Anonymous Crew".
	var (
		author string
		userID any // sql nullable
	)
	if user != nil {
		author = user.Username
		userID = user.ID
	} else {
		author = trimMax(r.PostFormValue("author"), 64)
		if author == "" {
			author = "Anonymous Crew"
		}
		userID = nil
	}

	if _, err := c.DB.Exec(
		`INSERT INTO comms_entries (user_id, author, body) VALUES (?, ?, ?)`,
		userID, author, body,
	); err != nil {
		log.Printf("comms submit insert: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// XSS detection: look for script tags, event handlers, or other markup.
	// PLANTED VULN a03-comms-stored-xss: if detected, flip the tracker row.
	if detectXSSPattern(body) {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := c.DB.Exec(flip, "a03-comms-stored-xss"); err != nil {
			log.Printf("comms XSS discover flip: %v", err)
		}
	}

	http.Redirect(w, r, "/comms", http.StatusSeeOther)
}

// Delete removes a comms entry. Admin-only. PLANTED VULN
// a09-comms-log-silent-delete: the destructive action writes no audit row —
// the entry simply vanishes. The tracker flips on the first such delete to
// surface the missing logging.
func (c *Comms) Delete(w http.ResponseWriter, r *http.Request) {
	user := requireAdmin(w, r, c.Session)
	if user == nil {
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	res, err := c.DB.Exec(`DELETE FROM comms_entries WHERE id = ?`, id)
	if err != nil {
		log.Printf("comms delete: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Intentionally NO audit log insert here. That gap is the lesson.

	if n, _ := res.RowsAffected(); n > 0 {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := c.DB.Exec(flip, "a09-comms-log-silent-delete"); err != nil {
			log.Printf("comms silent-delete discover flip: %v", err)
		}
	}

	http.Redirect(w, r, "/comms", http.StatusSeeOther)
}

// detectXSSPattern checks for common XSS payloads in a string.
func detectXSSPattern(s string) bool {
	lower := strings.ToLower(s)
	patterns := []string{
		"<script",
		"javascript:",
		"onerror=",
		"onload=",
		"onclick=",
		"onmouseover=",
		"<iframe",
		"<object",
		"<embed",
		"<img ",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
