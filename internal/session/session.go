// Package session wires the scs session manager with a SQLite-backed store.
// Sessions persist across server restarts because they live in the same
// orbital.sqlite file as the rest of the app's state.
package session

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
)

// Keys used in the session. Centralizing the names here keeps handlers in
// sync — a typo in "user_id" elsewhere becomes a compile error here.
const (
	KeyUserID   = "user_id"
	KeyUsername = "username"
	KeyIsAdmin  = "is_admin"
	KeyFlash    = "flash"
)

// New returns a configured scs.SessionManager that uses the provided SQLite
// connection for storage. The sessions table is created by db.Open via
// schema.sql, so no extra setup is required.
func New(conn *sql.DB) *scs.SessionManager {
	s := scs.New()
	s.Store = sqlite3store.New(conn)
	s.Lifetime = 24 * time.Hour
	s.IdleTimeout = 2 * time.Hour
	s.Cookie.Name = "orbital_session"
	s.Cookie.HttpOnly = true
	s.Cookie.SameSite = http.SameSiteLaxMode
	// Local-only training app: HTTP, no TLS. Flip to true once we ever add HTTPS.
	s.Cookie.Secure = false
	return s
}
