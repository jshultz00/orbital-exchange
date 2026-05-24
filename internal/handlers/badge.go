package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/session"
	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Badge is the planted A05:2025 — Injection handler for a05-login-sqli. It
// exposes the station's "express badge reader" — a quick-login path that
// trades the passphrase for a station-issued badge code (the same value as
// the user's station_key). The lookup query interpolates both fields
// directly into SQL, so a crafted input slips past the comparison.
type Badge struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const loginSQLiTrackerID = "a05-login-sqli"

// Form renders GET /badge — the express badge reader sign-in form.
func (b *Badge) Form(w http.ResponseWriter, r *http.Request) {
	data := pageData(r, b.Session, "Badge Reader")
	render(w, b.Views, "badge", data)
}

// Submit handles POST /badge. PLANTED VULN a05-login-sqli: the WHERE clause
// is built by string concatenation, so input like
//
//	callsign:  command' --
//	badge:     anything
//
// (or `' OR '1'='1' --` in either field) makes the comparison vacuously true
// and the first matching row is signed in.
func (b *Badge) Submit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	callsign := r.PostFormValue("callsign")
	badge := r.PostFormValue("badge")

	// PLANTED VULN a05-login-sqli: raw string interpolation. The whole point
	// of the lesson — never do this. Use parameter placeholders instead.
	query := fmt.Sprintf(
		`SELECT id, username, is_admin FROM users WHERE username = '%s' AND station_key = '%s' LIMIT 1`,
		callsign, badge,
	)

	var (
		id      int64
		uname   string
		isAdmin int
	)
	err := b.DB.QueryRow(query).Scan(&id, &uname, &isAdmin)
	if err == sql.ErrNoRows {
		b.renderError(w, r, callsign, "Badge unrecognized. Try again or use the standard sign-in.")
		return
	}
	if err != nil {
		// A successful syntax-error from a probe still teaches the lesson —
		// surface it as the badge reader complaining about its own query.
		b.renderError(w, r, callsign, "Badge reader error: "+err.Error())
		return
	}

	// Tracker flip: if the row we matched does not correspond to the typed
	// callsign, the comparison was bypassed — that's the injection signal.
	typed := strings.TrimSpace(callsign)
	if typed != "" && !strings.EqualFold(typed, uname) {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := b.DB.Exec(flip, loginSQLiTrackerID); err != nil {
			log.Printf("badge login-sqli discover flip: %v", err)
		}
	}

	if err := b.Session.RenewToken(r.Context()); err != nil {
		log.Printf("badge login renew: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	b.Session.Put(r.Context(), session.KeyUserID, int(id))
	b.Session.Put(r.Context(), session.KeyUsername, uname)
	b.Session.Put(r.Context(), session.KeyIsAdmin, isAdmin == 1)
	b.Session.Put(r.Context(), session.KeyFlash, "Badge accepted. Signed in as "+uname+".")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (b *Badge) renderError(w http.ResponseWriter, r *http.Request, callsign, msg string) {
	data := pageData(r, b.Session, "Badge Reader")
	data["Error"] = msg
	data["Callsign"] = callsign
	w.WriteHeader(http.StatusUnauthorized)
	render(w, b.Views, "badge", data)
}
