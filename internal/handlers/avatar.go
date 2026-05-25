package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Avatar serves the crew avatar upload bench. Three planted vulns live here:
//
//   a03-deprecated-image-parser: uploads are handed to a retired ImageMagick
//   6.9.2-era profile parser that accepts MVG/SVG directives embedded in
//   "image" files. A crafted ImageTragick-style payload proves the parser
//   is reachable and flips the tracker.
//
//   a01-avatar-path-traversal: persisted uploads use header.Filename verbatim
//   via filepath.Join, so a filename like "../css/theme.css" lands outside
//   the avatars directory. Detection: resolved path escapes the drop zone.
//
//   a05-avatar-svg-xss: SVG avatars are inlined into the crew profile HTML
//   for styling control (see crew_detail.html). An SVG carrying a <script>
//   block executes in any viewer's browser. Detection at upload time: an
//   uploaded .svg contains a <script tag.
type Avatar struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const (
	deprecatedImageParserTrackerID = "a03-deprecated-image-parser"
	avatarPathTraversalTrackerID   = "a01-avatar-path-traversal"
	avatarSVGXSSTrackerID          = "a05-avatar-svg-xss"

	// avatarDropZone is the on-disk directory uploads should land in. Paths
	// resolving outside this directory after filepath.Join trigger the
	// path-traversal tracker.
	avatarDropZone = "public/avatars"

	// DefaultAvatarURL is the served path for the bundled crew-badge SVG
	// shown to users who have not uploaded a custom avatar.
	DefaultAvatarURL = "/static/avatars/default.svg"

	// maxAvatarSize caps a single upload at 1 MiB. The cap is intentional:
	// it prevents disk-fill DoS but is large enough that the planted vulns
	// stay reachable with realistic payloads.
	maxAvatarSize = 1 << 20
)

type avatarParseResult struct {
	Filename string
	Size     int
	Parser   string
	Notes    []string
}

func (a *Avatar) Form(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, a.Session)
	if user == nil {
		return
	}

	data := pageData(r, a.Session, "Avatar Uplink")
	data["CurrentAvatarURL"] = a.currentAvatarURL(user.ID)
	render(w, a.Views, "avatar", data)
}

func (a *Avatar) Upload(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, a.Session)
	if user == nil {
		return
	}

	if err := r.ParseMultipartForm(maxAvatarSize); err != nil {
		a.renderUpload(w, r, user, nil, "Upload rejected by the docking clamp.")
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		a.renderUpload(w, r, user, nil, "Select an avatar packet first.")
		return
	}
	defer file.Close()

	body, err := io.ReadAll(io.LimitReader(file, maxAvatarSize))
	if err != nil {
		log.Printf("avatar upload read: %v", err)
		http.Error(w, "upload read failed", http.StatusInternalServerError)
		return
	}

	result := parseLegacyAvatar(header.Filename, body)
	if result == nil {
		a.renderUpload(w, r, user, nil, "The legacy parser returned no telemetry.")
		return
	}

	// Persist the upload. PLANTED VULN a01-avatar-path-traversal: the raw
	// Content-Disposition "filename" parameter is fed straight into
	// filepath.Join. (mime/multipart.Part.FileName() strips path components
	// per RFC 7578, but the developer here reached past it to the original
	// MIME header — a realistic "I wanted the real filename" mistake.)
	// A "../something" payload resolves to a sibling of avatarDropZone, far
	// enough to overwrite served static assets (e.g. css/theme.css).
	rawName := rawDispositionFilename(header)
	if rawName == "" {
		rawName = strings.TrimSpace(header.Filename)
	}
	if rawName == "" {
		rawName = "avatar.bin"
	}
	if err := os.MkdirAll(avatarDropZone, 0o755); err != nil {
		log.Printf("avatar drop zone create: %v", err)
		http.Error(w, "storage unavailable", http.StatusInternalServerError)
		return
	}
	storedPath := filepath.Join(avatarDropZone, rawName)
	if err := os.MkdirAll(filepath.Dir(storedPath), 0o755); err != nil {
		log.Printf("avatar parent dir create: %v", err)
		http.Error(w, "storage unavailable", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(storedPath, body, 0o644); err != nil {
		log.Printf("avatar write %s: %v", storedPath, err)
		http.Error(w, "storage write failed", http.StatusInternalServerError)
		return
	}

	// Detection: did the resolved path escape the drop zone? Compare the
	// absolute resolved path to the absolute drop-zone root.
	if escaped, where := pathEscapedDropZone(storedPath); escaped {
		result.Notes = append(result.Notes, fmt.Sprintf("file landed at %s (outside drop zone)", where))
		a.flipTracker(avatarPathTraversalTrackerID)
	}

	// Update users.avatar_path. We point the column at the canonical served
	// URL (/static/avatars/<basename>) — even if the file traversed elsewhere,
	// the user record still tries to display from the intended dir, which
	// keeps the page from breaking after a successful traversal.
	relForUser := filepath.ToSlash(filepath.Join("/static/avatars", filepath.Base(rawName)))
	if _, err := a.DB.Exec(`UPDATE users SET avatar_path = ? WHERE id = ?`, relForUser, user.ID); err != nil {
		log.Printf("avatar db update %d: %v", user.ID, err)
		http.Error(w, "storage update failed", http.StatusInternalServerError)
		return
	}

	// ImageTragick probe — same detection as before, just routed through the
	// new flipTracker helper.
	if containsImageTragickProbe(header.Filename, body) {
		result.Notes = append(result.Notes, "delegate directive accepted: CVE-2016-3714 proof reached the retired parser")
		a.flipTracker(deprecatedImageParserTrackerID)
	}

	// SVG-XSS probe: an SVG carrying a <script> tag means the uploader is
	// expecting the crew profile to inline-render it. The crew page does.
	if isSVG(header.Filename, body) && containsSVGScript(body) {
		result.Notes = append(result.Notes, "<script> block detected in SVG payload — will execute when crew profile inlines it")
		a.flipTracker(avatarSVGXSSTrackerID)
	}

	a.renderUpload(w, r, user, result, "")
}

func (a *Avatar) flipTracker(id string) {
	const flip = `
		UPDATE vulnerabilities
		SET status = 'discovered',
		    discovered_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'undiscovered'
	`
	if _, err := a.DB.Exec(flip, id); err != nil {
		log.Printf("avatar tracker flip %s: %v", id, err)
	}
}

// currentAvatarURL returns the served URL for the user's avatar, falling back
// to the bundled default badge when the user has not uploaded one.
func (a *Avatar) currentAvatarURL(userID int64) string {
	var path string
	if err := a.DB.QueryRow(`SELECT avatar_path FROM users WHERE id = ?`, userID).Scan(&path); err != nil {
		return DefaultAvatarURL
	}
	if path == "" {
		return DefaultAvatarURL
	}
	return path
}

func (a *Avatar) renderUpload(w http.ResponseWriter, r *http.Request, user *User, result *avatarParseResult, msg string) {
	data := pageData(r, a.Session, "Avatar Uplink")
	data["Result"] = result
	data["Error"] = msg
	data["CurrentAvatarURL"] = a.currentAvatarURL(user.ID)
	render(w, a.Views, "avatar", data)
}

// rawDispositionFilename extracts the filename parameter from the raw
// Content-Disposition header on a multipart file, preserving any path
// components (e.g. "../foo"). The standard library's FileHeader.Filename
// runs filepath.Base() on this value first, which would defeat the
// planted a01-avatar-path-traversal surface — so we reach past it.
func rawDispositionFilename(header *multipart.FileHeader) string {
	disposition := header.Header.Get("Content-Disposition")
	if disposition == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		return ""
	}
	return params["filename"]
}

// pathEscapedDropZone resolves storedPath and avatarDropZone to absolute paths
// and reports whether storedPath sits outside the drop zone. The second return
// is the resolved path for human-readable logging.
func pathEscapedDropZone(storedPath string) (bool, string) {
	absZone, err := filepath.Abs(avatarDropZone)
	if err != nil {
		return false, storedPath
	}
	absPath, err := filepath.Abs(storedPath)
	if err != nil {
		return false, storedPath
	}
	rel, err := filepath.Rel(absZone, absPath)
	if err != nil {
		return true, absPath
	}
	// If the relative path starts with ".." the file is outside the zone.
	return strings.HasPrefix(rel, ".."), absPath
}

func isSVG(filename string, body []byte) bool {
	if strings.EqualFold(filepath.Ext(filename), ".svg") {
		return true
	}
	head := strings.ToLower(string(body[:minInt(256, len(body))]))
	return strings.Contains(head, "<svg")
}

func containsSVGScript(body []byte) bool {
	text := strings.ToLower(string(body))
	return strings.Contains(text, "<script")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseLegacyAvatar(filename string, body []byte) *avatarParseResult {
	name := filepath.Base(filename)
	if name == "." || name == "/" {
		name = "unnamed"
	}

	result := &avatarParseResult{
		Filename: name,
		Size:     len(body),
		Parser:   "ImageMagick 6.9.2-10 legacy profile bridge",
	}

	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".mvg", ".svg", ".png", ".jpg", ".jpeg", ".gif":
		result.Notes = append(result.Notes, fmt.Sprintf("extension %s routed to legacy delegate path", ext))
	default:
		result.Notes = append(result.Notes, "unknown extension, but parser attempted salvage anyway")
	}

	text := strings.ToLower(string(body))
	if strings.Contains(text, "profile") || strings.Contains(text, "comment") {
		result.Notes = append(result.Notes, "metadata profile block extracted")
	}
	if strings.Contains(text, "push graphic-context") {
		result.Notes = append(result.Notes, "MVG graphic context detected")
	}
	if strings.Contains(text, "url(") {
		result.Notes = append(result.Notes, "external URL delegate token preserved")
	}
	if len(result.Notes) == 0 {
		result.Notes = append(result.Notes, "no profile metadata found")
	}
	return result
}

func containsImageTragickProbe(filename string, body []byte) bool {
	text := strings.ToLower(string(body))
	ext := strings.ToLower(filepath.Ext(filename))
	hasLegacyExtension := ext == ".mvg" || ext == ".svg" || ext == ".png"
	hasDelegateDirective := strings.Contains(text, "push graphic-context") && strings.Contains(text, "url(")
	hasPublicCVE := strings.Contains(text, "cve-2016-3714") || strings.Contains(text, "imagetragick")
	return hasLegacyExtension && hasDelegateDirective && hasPublicCVE
}
