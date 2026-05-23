package handlers

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/alexedwards/scs/v2"
	"golang.org/x/crypto/bcrypt"

	"github.com/jshultz00/orbital-exchange/internal/session"
	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Auth handles register, login, and logout.
//
// Defensive baseline (no vulns planted yet):
//   - bcrypt for password storage (cost 12)
//   - session token rotated on login via sess.RenewToken to defeat fixation
//   - generic "credentials invalid" errors so we don't leak which field was wrong
//   - parameterized SQL throughout
type Auth struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const bcryptCost = 12

// ----- GET forms -----

// LoginForm renders /login.
func (a *Auth) LoginForm(w http.ResponseWriter, r *http.Request) {
	data := pageData(r, a.Session, "Sign In")
	data["Mode"] = "login"
	render(w, a.Views, "auth", data)
}

// RegisterForm renders /register.
func (a *Auth) RegisterForm(w http.ResponseWriter, r *http.Request) {
	data := pageData(r, a.Session, "Register")
	data["Mode"] = "register"
	render(w, a.Views, "auth", data)
}

// ----- POST handlers -----

// Login authenticates a user and starts a session.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")

	const q = `SELECT id, username, password_hash, is_admin FROM users WHERE username = ?`
	var (
		id      int64
		uname   string
		hash    string
		isAdmin int
	)
	err := a.DB.QueryRow(q, username).Scan(&id, &uname, &hash, &isAdmin)
	if errors.Is(err, sql.ErrNoRows) {
		a.renderError(w, r, "login", "Invalid credentials.")
		return
	}
	if err != nil {
		log.Printf("auth login lookup: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		a.renderError(w, r, "login", "Invalid credentials.")
		return
	}

	// Rotate the session token on auth boundary — prevents fixation.
	if err := a.Session.RenewToken(r.Context()); err != nil {
		log.Printf("auth login renew: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.Session.Put(r.Context(), session.KeyUserID, int(id))
	a.Session.Put(r.Context(), session.KeyUsername, uname)
	a.Session.Put(r.Context(), session.KeyIsAdmin, isAdmin == 1)
	a.Session.Put(r.Context(), session.KeyFlash, "Signed in as "+uname+".")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Register creates a new crew account and signs them in.
func (a *Auth) Register(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")

	if msg := validateRegistration(username, password); msg != "" {
		a.renderError(w, r, "register", msg)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		log.Printf("auth register hash: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	const insert = `INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)`
	res, err := a.DB.Exec(insert, username, string(hash))
	if err != nil {
		// SQLite UNIQUE violation: username already exists.
		if strings.Contains(err.Error(), "UNIQUE") {
			a.renderError(w, r, "register", "That callsign is already taken.")
			return
		}
		log.Printf("auth register insert: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	id, _ := res.LastInsertId()

	if err := a.Session.RenewToken(r.Context()); err != nil {
		log.Printf("auth register renew: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.Session.Put(r.Context(), session.KeyUserID, int(id))
	a.Session.Put(r.Context(), session.KeyUsername, username)
	a.Session.Put(r.Context(), session.KeyIsAdmin, false)
	a.Session.Put(r.Context(), session.KeyFlash, "Welcome aboard, "+username+".")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Logout destroys the session and redirects home.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if err := a.Session.Destroy(r.Context()); err != nil {
		log.Printf("auth logout: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// renderError re-renders the auth form with an error message and preserves
// the typed-in username so the user doesn't have to retype it.
func (a *Auth) renderError(w http.ResponseWriter, r *http.Request, mode, msg string) {
	data := pageData(r, a.Session, "Sign In")
	data["Mode"] = mode
	data["Error"] = msg
	data["Username"] = r.PostFormValue("username")
	w.WriteHeader(http.StatusUnauthorized)
	render(w, a.Views, "auth", data)
}

// validateRegistration enforces a minimal but real policy. Returns "" if OK,
// otherwise the user-facing error message.
//
// Deliberately strong by default — A07 "weak password policy" exists as a
// planned planted vuln. When that one is planted, this function (or its
// caller) is the natural place to weaken.
func validateRegistration(username, password string) string {
	if username == "" {
		return "Crew callsign is required."
	}
	if len(username) > 32 {
		return "Crew callsign must be 32 characters or fewer."
	}
	for _, r := range username {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.'
		if !ok {
			return "Crew callsign may only contain letters, numbers, underscore, dash, or period."
		}
	}
	if len(password) < 10 {
		return "Passphrase must be at least 10 characters."
	}
	if len(password) > 256 {
		return "Passphrase must be 256 characters or fewer."
	}
	return ""
}
