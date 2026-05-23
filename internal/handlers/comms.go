package handlers

import (
	"database/sql"
	"log"
	"net/http"

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
	ID         int64
	Author     string
	Body       string
	CreatedAt  string // pre-formatted in SQL for simplicity
	FromCrew   bool   // true if user_id is non-NULL — UI styles authed entries
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
		if err := rows.Scan(&e.ID, &e.Author, &e.Body, &e.CreatedAt, &e.FromCrew); err != nil {
			log.Printf("comms list scan: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
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

	http.Redirect(w, r, "/comms", http.StatusSeeOther)
}
