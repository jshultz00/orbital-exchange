package handlers

import (
	"database/sql"
	"net/http"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Pages holds handlers for static-ish pages that need session-aware nav but
// little else (landing today; 404 later).
type Pages struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// Landing renders the bulletin / home page.
func (p *Pages) Landing(w http.ResponseWriter, r *http.Request) {
	render(w, p.Views, "landing", pageData(r, p.Session, "Bulletin"))
}

// Bridge renders the bridge operations hub: a single index of the logistics,
// cargo, and clearance consoles (supply drop, cargo import/bundle, pre-auth,
// patch channel, restricted dossier, shuttle pass) so they don't each need
// their own top-level navbar entry.
func (p *Pages) Bridge(w http.ResponseWriter, r *http.Request) {
	if requireLogin(w, r, p.Session) == nil {
		return
	}
	render(w, p.Views, "bridge_index", pageData(r, p.Session, "Bridge"))
}

// NotFound renders the styled 404 page. Registered as the mux "/" catch-all
// in main, so any path that no more-specific pattern claims lands here.
func (p *Pages) NotFound(w http.ResponseWriter, r *http.Request) {
	// Content-Type header must be set before WriteHeader; render() sets it.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	data := pageData(r, p.Session, "Signal Lost")
	data["Path"] = r.URL.Path
	if err := p.Views.Render(w, "404", data); err != nil {
		// Status is already written; just log.
		_ = err
	}
}
