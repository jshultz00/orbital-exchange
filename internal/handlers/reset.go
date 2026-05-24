package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"golang.org/x/crypto/bcrypt"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Reset handles the crew password-reset flow. PLANTED VULN
// a06-password-reset-flow: the confirm step validates a token, resets the
// password, but never marks the token spent. A token can be replayed as long
// as it hasn't expired — the lesson is "one-shot tokens must actually be
// one-shot." Because there's no email infrastructure in the training app,
// the issued token is displayed directly on the page along with a
// pre-built confirm link, so the crew member can complete the flow locally.
type Reset struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const (
	passwordResetTrackerID = "a06-password-reset-flow"
	resetTokenTTL          = 30 * time.Minute
)

// RequestForm renders GET /reset — the username-entry form.
func (rs *Reset) RequestForm(w http.ResponseWriter, r *http.Request) {
	data := pageData(r, rs.Session, "Password Reset")
	data["Mode"] = "request"
	render(w, rs.Views, "reset", data)
}

// Request handles POST /reset. Issues a token for the requested user if they
// exist. To avoid breaking the training flow, the token (and confirm link) is
// displayed directly on the response page rather than emailed.
func (rs *Reset) Request(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))

	data := pageData(r, rs.Session, "Password Reset")
	data["Mode"] = "request"
	data["Username"] = username

	if username == "" {
		data["Error"] = "Crew callsign is required."
		render(w, rs.Views, "reset", data)
		return
	}

	var userID int64
	err := rs.DB.QueryRow(`SELECT id FROM users WHERE username = ?`, username).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		// Don't reveal whether the user exists — but in the training app we
		// also can't issue a token, so render a generic "if this exists you'd
		// get one" message.
		data["Info"] = "If that callsign is on file, a reset beacon has been queued."
		render(w, rs.Views, "reset", data)
		return
	}
	if err != nil {
		log.Printf("reset request lookup: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	token, err := generateResetToken()
	if err != nil {
		log.Printf("reset request token: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	expires := time.Now().Add(resetTokenTTL)
	if _, err := rs.DB.Exec(
		`INSERT INTO password_resets (token, user_id, expires_at) VALUES (?, ?, ?)`,
		token, userID, expires,
	); err != nil {
		log.Printf("reset request insert: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data["Token"] = token
	data["ConfirmPath"] = "/reset/confirm?token=" + token
	data["Username"] = username
	render(w, rs.Views, "reset", data)
}

// ConfirmForm renders GET /reset/confirm — the new-passphrase form. The token
// arrives in the query string.
func (rs *Reset) ConfirmForm(w http.ResponseWriter, r *http.Request) {
	data := pageData(r, rs.Session, "Password Reset")
	data["Mode"] = "confirm"
	data["Token"] = r.URL.Query().Get("token")
	render(w, rs.Views, "reset", data)
}

// Confirm handles POST /reset/confirm. PLANTED VULN a06-password-reset-flow:
// the token is validated (exists + not expired) and the password is updated,
// but use_count is only incremented — the token is NEVER deleted or marked
// spent. Replaying the same token resets the password again. The tracker
// flips when any token's use_count rises above 1.
func (rs *Reset) Confirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	token := r.PostFormValue("token")
	password := r.PostFormValue("password")

	data := pageData(r, rs.Session, "Password Reset")
	data["Mode"] = "confirm"
	data["Token"] = token

	if token == "" || password == "" {
		data["Error"] = "Token and new passphrase are required."
		render(w, rs.Views, "reset", data)
		return
	}
	if len(password) > 256 {
		data["Error"] = "Passphrase must be 256 characters or fewer."
		render(w, rs.Views, "reset", data)
		return
	}

	var (
		userID    int64
		expiresAt time.Time
		useCount  int
	)
	err := rs.DB.QueryRow(
		`SELECT user_id, expires_at, use_count FROM password_resets WHERE token = ?`,
		token,
	).Scan(&userID, &expiresAt, &useCount)
	if errors.Is(err, sql.ErrNoRows) {
		data["Error"] = "Unknown reset token."
		render(w, rs.Views, "reset", data)
		return
	}
	if err != nil {
		log.Printf("reset confirm lookup: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if time.Now().After(expiresAt) {
		data["Error"] = "Reset token has expired."
		render(w, rs.Views, "reset", data)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		log.Printf("reset confirm hash: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := rs.DB.Exec(
		`UPDATE users SET password_hash = ? WHERE id = ?`, string(hash), userID,
	); err != nil {
		log.Printf("reset confirm update: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// PLANTED VULN: bump the use counter but DO NOT mark the token spent
	// or delete it. Replays succeed.
	if _, err := rs.DB.Exec(
		`UPDATE password_resets SET use_count = use_count + 1 WHERE token = ?`, token,
	); err != nil {
		log.Printf("reset confirm bump: %v", err)
	}

	if useCount+1 >= 2 {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := rs.DB.Exec(flip, passwordResetTrackerID); err != nil {
			log.Printf("reset replay discover flip: %v", err)
		}
	}

	data["Success"] = "Passphrase reset. You can now sign in with the new credentials."
	render(w, rs.Views, "reset", data)
}

func generateResetToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
