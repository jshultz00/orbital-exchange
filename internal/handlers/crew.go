package handlers

import (
	"database/sql"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Crew serves individual crew member roster entries.
//
// Planted vulns surfaced here:
//
//   a01-crew-roster-idor: the Detail handler looks up crew by ID alone,
//   with no check that the crew member is the session user.
//
//   a05-avatar-svg-xss: when the crew member's avatar is an SVG, Detail
//   reads the file bytes from disk and hands them to the template as
//   template.HTML so the renderer skips escaping. An attacker-supplied
//   SVG with <script> executes in any viewer's browser.
type Crew struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const crewIDORTrackerID = "a01-crew-roster-idor"

// CrewDetail is the full crew member record for the detail view.
// StationKey is the API token used to authenticate against /manifest/export.
// Showing it here without an ownership check is the planted IDOR surface.
//
// AvatarInlineSVG carries the raw bytes of the user's SVG avatar (if any) so
// the template can drop them straight into the page. It is empty for non-SVG
// avatars and for the default badge, which are served via <img>.
type CrewDetail struct {
	ID              int64
	Username        string
	IsAdmin         bool
	StationKey      string
	CreatedAt       string
	AvatarURL       string
	AvatarInlineSVG template.HTML
}

// Index renders /crew. Admins see the full roster; regular crew see only
// their own entry. The legitimate UI never exposes other crew IDs to a
// non-admin viewer — but /crew/{id} has no ownership check, so anyone can
// still read any record by guessing sequential IDs directly. That gap is
// the planted IDOR (a01-crew-roster-idor).
func (c *Crew) Index(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}

	q := `
		SELECT id, username, is_admin = 1, avatar_path,
		       strftime('%Y-%m-%d %H:%M', created_at)
		FROM users
		ORDER BY id ASC
	`
	args := []any{}
	if !user.IsAdmin {
		q = `
			SELECT id, username, is_admin = 1, avatar_path,
			       strftime('%Y-%m-%d %H:%M', created_at)
			FROM users
			WHERE id = ?
		`
		args = append(args, user.ID)
	}
	rows, err := c.DB.Query(q, args...)
	if err != nil {
		log.Printf("crew index: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var roster []CrewRow
	for rows.Next() {
		var row CrewRow
		var avatarPath string
		if err := rows.Scan(&row.ID, &row.Username, &row.IsAdmin, &avatarPath, &row.CreatedAt); err != nil {
			log.Printf("crew index scan: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		row.AvatarURL = avatarURLOrDefault(avatarPath)
		roster = append(roster, row)
	}

	data := pageData(r, c.Session, "Crew Roster")
	data["Roster"] = roster
	render(w, c.Views, "crew_index", data)
}

// Detail renders /crew/{id}. PLANTED VULN: this handler does not verify
// that the crew member's id matches the session — any logged-in crew member
// can pull any crew member's record by ID.
func (c *Crew) Detail(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}

	const q = `
		SELECT id, username, is_admin = 1, station_key, avatar_path,
		       strftime('%Y-%m-%d %H:%M', created_at)
		FROM users
		WHERE id = ?
	`
	var detail CrewDetail
	var avatarPath string
	err = c.DB.QueryRow(q, id).Scan(
		&detail.ID, &detail.Username, &detail.IsAdmin, &detail.StationKey,
		&avatarPath, &detail.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("crew detail %d: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	detail.AvatarURL = avatarURLOrDefault(avatarPath)
	// PLANTED VULN a05-avatar-svg-xss: SVG avatars are inlined directly into
	// the page for "styling control". template.HTML marks the bytes as
	// pre-escaped so html/template emits them verbatim — including any
	// <script> tags the uploader smuggled in.
	if svg, ok := readAvatarSVG(avatarPath); ok {
		detail.AvatarInlineSVG = template.HTML(svg) //nolint:gosec // intentional XSS surface
	}

	// IDOR detection: flip the tracker when a regular (non-admin) crew member
	// views someone else's record. Admins legitimately browse the roster, so
	// their access doesn't count as exploitation.
	if detail.ID != user.ID && !user.IsAdmin {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := c.DB.Exec(flip, crewIDORTrackerID); err != nil {
			log.Printf("crew IDOR discover flip: %v", err)
		}
	}

	data := pageData(r, c.Session, "Crew Member "+detail.Username)
	data["Crew"] = detail
	data["IsOwn"] = detail.ID == user.ID
	render(w, c.Views, "crew_detail", data)
}

// avatarURLOrDefault maps a users.avatar_path value to a renderable URL.
// Empty paths fall back to the bundled default crew-badge SVG.
func avatarURLOrDefault(path string) string {
	if path == "" {
		return DefaultAvatarURL
	}
	return path
}

// readAvatarSVG reads the on-disk SVG that backs avatar_path and returns its
// raw bytes for inline rendering. Returns (_, false) for empty paths, non-SVG
// avatars, or read errors — callers fall back to <img> rendering of the URL.
func readAvatarSVG(avatarPath string) ([]byte, bool) {
	if avatarPath == "" {
		return nil, false
	}
	if !strings.EqualFold(filepath.Ext(avatarPath), ".svg") {
		return nil, false
	}
	// avatarPath is a served URL like "/static/avatars/foo.svg". Map it back
	// to the on-disk file under public/. Use only the basename to keep the
	// disk read scoped to the drop zone — the planted traversal is at write
	// time, not here at read time.
	diskPath := filepath.Join(avatarDropZone, filepath.Base(avatarPath))
	body, err := os.ReadFile(diskPath)
	if err != nil {
		return nil, false
	}
	return body, true
}
