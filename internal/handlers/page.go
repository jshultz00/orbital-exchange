package handlers

import (
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/session"
)

// User is the lightweight session-derived user record passed to templates.
// It is nil when the request is unauthenticated.
type User struct {
	ID       int64
	Username string
	IsAdmin  bool
}

// pageData builds the base map every page template expects: Title, Year,
// User, Flash. Handlers extend it with their own keys before calling render.
//
// The session manager is the source of truth for who the user is — handlers
// must wrap their mux with sess.LoadAndSave so the request context carries
// session data.
func pageData(r *http.Request, sess *scs.SessionManager, title string) map[string]any {
	data := map[string]any{
		"Title": title,
		"Year":  time.Now().Year(),
		"User":  currentUser(r, sess),
	}
	if flash := sess.PopString(r.Context(), session.KeyFlash); flash != "" {
		data["Flash"] = flash
	}
	return data
}

// currentUser reconstructs the User from session storage, or returns nil if
// the session has no user_id.
func currentUser(r *http.Request, sess *scs.SessionManager) *User {
	id := sess.GetInt(r.Context(), session.KeyUserID)
	if id == 0 {
		return nil
	}
	return &User{
		ID:       int64(id),
		Username: sess.GetString(r.Context(), session.KeyUsername),
		IsAdmin:  sess.GetBool(r.Context(), session.KeyIsAdmin),
	}
}

// requireLogin returns the current user, or writes a redirect to /login and
// returns nil. Handlers should bail immediately on a nil return.
func requireLogin(w http.ResponseWriter, r *http.Request, sess *scs.SessionManager) *User {
	user := currentUser(r, sess)
	if user == nil {
		sess.Put(r.Context(), session.KeyFlash, "Please sign in first.")
		if r.Method == http.MethodGet {
			sess.Put(r.Context(), "return_to", r.URL.Path)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil
	}
	return user
}

// requireAdmin returns the current user iff they are an admin; otherwise it
// writes a 403 and returns nil. Unauthenticated requests are redirected to
// /login (via requireLogin).
func requireAdmin(w http.ResponseWriter, r *http.Request, sess *scs.SessionManager) *User {
	user := requireLogin(w, r, sess)
	if user == nil {
		return nil
	}
	if !user.IsAdmin {
		http.Error(w, "Station Command access only.", http.StatusForbidden)
		return nil
	}
	return user
}
