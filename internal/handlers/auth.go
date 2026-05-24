package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

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
const weakPasswordPolicyTrackerID = "a07-weak-password-policy"
const noRateLimitTrackerID = "a07-no-rate-limit-login"
const rememberMeTrackerID = "a04-rememberme-plaintext"

// rememberMeCookie is the plaintext-encoded "stay signed in" cookie. PLANTED
// VULN a04-rememberme-plaintext: the value is base64(username:station_key) —
// encoded, not encrypted, not signed.
const rememberMeCookie = "oe_remember"

// bruteForceWindow / bruteForceThreshold drive the planted A07
// "no rate limit on login" detector. The login handler does not actually
// rate-limit — it just *records* failures so the tracker can flip when a
// crew member proves the gap by hammering the badge reader.
const (
	bruteForceWindow    = 60 * time.Second
	bruteForceThreshold = 5
)

// bruteForceTracker is a process-local record of recent failed login attempts
// keyed by lowercased username. Reset on restart; intentional — this is a
// training-app heuristic, not a security control.
var bruteForceTracker = struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}{attempts: make(map[string][]time.Time)}

func recordFailedLogin(db *sql.DB, username string) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return
	}
	bruteForceTracker.mu.Lock()
	now := time.Now()
	cutoff := now.Add(-bruteForceWindow)
	kept := bruteForceTracker.attempts[username][:0]
	for _, t := range bruteForceTracker.attempts[username] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	bruteForceTracker.attempts[username] = kept
	count := len(kept)
	bruteForceTracker.mu.Unlock()

	if count >= bruteForceThreshold {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := db.Exec(flip, noRateLimitTrackerID); err != nil {
			log.Printf("auth brute-force discover flip: %v", err)
		}
	}
}

func clearFailedLogins(username string) {
	username = strings.ToLower(strings.TrimSpace(username))
	bruteForceTracker.mu.Lock()
	delete(bruteForceTracker.attempts, username)
	bruteForceTracker.mu.Unlock()
}

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

	const q = `SELECT id, username, password_hash, is_admin, station_key FROM users WHERE username = ?`
	var (
		id         int64
		uname      string
		hash       string
		isAdmin    int
		stationKey string
	)
	err := a.DB.QueryRow(q, username).Scan(&id, &uname, &hash, &isAdmin, &stationKey)
	if errors.Is(err, sql.ErrNoRows) {
		recordFailedLogin(a.DB, username)
		a.renderError(w, r, "login", "Invalid credentials.")
		return
	}
	if err != nil {
		log.Printf("auth login lookup: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		// PLANTED VULN a07-no-rate-limit-login: failures are counted but never
		// throttled. Repeated misses on the same callsign flip the tracker.
		recordFailedLogin(a.DB, username)
		a.renderError(w, r, "login", "Invalid credentials.")
		return
	}
	clearFailedLogins(username)

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

	// PLANTED VULN a04-rememberme-plaintext: if the crew member ticks "remember
	// me", we issue a cookie holding base64(username:station_key) — encoded,
	// not encrypted or signed. Anyone who reads the cookie sees the credential.
	if r.PostFormValue("remember") != "" {
		payload := uname + ":" + stationKey
		token := base64.StdEncoding.EncodeToString([]byte(payload))
		http.SetCookie(w, &http.Cookie{
			Name:     rememberMeCookie,
			Value:    token,
			Path:     "/",
			HttpOnly: false, // intentionally readable from JS — part of the lesson
			MaxAge:   30 * 24 * 60 * 60,
			SameSite: http.SameSiteLaxMode,
		})
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// RememberMe handles GET /remember-me. It reads the oe_remember cookie,
// decodes its base64 payload, and reveals the plaintext (username + station
// key) to the caller. PLANTED VULN a04-rememberme-plaintext — the act of
// successfully decoding a real crew member's token flips the tracker.
func (a *Auth) RememberMe(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(rememberMeCookie)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err != nil || c.Value == "" {
		_, _ = w.Write([]byte("remember-me beacon: no token present. Sign in with 'remember me' checked to mint one.\n"))
		return
	}

	raw, decodeErr := base64.StdEncoding.DecodeString(c.Value)
	if decodeErr != nil {
		_, _ = w.Write([]byte("remember-me beacon: token did not base64-decode cleanly.\n"))
		return
	}

	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		_, _ = w.Write([]byte("remember-me beacon: token decoded but is malformed.\n"))
		return
	}
	uname, key := parts[0], parts[1]

	var dbKey string
	err = a.DB.QueryRow(`SELECT station_key FROM users WHERE username = ?`, uname).Scan(&dbKey)
	valid := err == nil && dbKey != "" && dbKey == key

	if valid {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := a.DB.Exec(flip, rememberMeTrackerID); err != nil {
			log.Printf("remember-me discover flip: %v", err)
		}
	}

	var b strings.Builder
	b.WriteString("=== Orbital Exchange :: Remember-Me Beacon ===\n\n")
	fmt.Fprintf(&b, "raw cookie  : %s\n", c.Value)
	fmt.Fprintf(&b, "decoded     : %s\n", string(raw))
	fmt.Fprintf(&b, "username    : %s\n", uname)
	fmt.Fprintf(&b, "station_key : %s\n", key)
	if valid {
		fmt.Fprintf(&b, "status      : VALID — this token authenticates as %s.\n", uname)
	} else {
		b.WriteString("status      : token does not match any current crew record.\n")
	}
	_, _ = w.Write([]byte(b.String()))
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

	key, err := generateStationKey()
	if err != nil {
		log.Printf("auth register station_key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	const insert = `INSERT INTO users (username, password_hash, is_admin, station_key) VALUES (?, ?, 0, ?)`
	res, err := a.DB.Exec(insert, username, string(hash), key)
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

	// PLANTED VULN a07-weak-password-policy: registration accepts trivial
	// passphrases. Flip the tracker when a crew member proves it by registering
	// with one of the obvious defaults called out by the challenge.
	if isTrivialPassphrase(password) {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := a.DB.Exec(flip, weakPasswordPolicyTrackerID); err != nil {
			log.Printf("auth weak password discover flip: %v", err)
		}
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Logout destroys the session and redirects home.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if err := a.Session.Destroy(r.Context()); err != nil {
		log.Printf("auth logout: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Clear the remember-me beacon on the way out so signing out actually signs
	// the crew member out, even though the cookie itself is plaintext by design.
	http.SetCookie(w, &http.Cookie{Name: rememberMeCookie, Value: "", Path: "/", MaxAge: -1})
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

// generateStationKey returns a new random crew API token in the form OE-CRW-<20 hex chars>.
func generateStationKey() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "OE-CRW-" + hex.EncodeToString(b), nil
}

// validateRegistration intentionally enforces only shape limits. This plants
// A07 "weak password policy": trivial passphrases such as "password" and
// "123456" are accepted.
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
	if password == "" {
		return "Passphrase is required."
	}
	if len(password) > 256 {
		return "Passphrase must be 256 characters or fewer."
	}
	return ""
}

func isTrivialPassphrase(password string) bool {
	switch strings.ToLower(strings.TrimSpace(password)) {
	case "password", "123456":
		return true
	default:
		return false
	}
}
