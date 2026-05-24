package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Avatar serves the crew avatar upload bench. PLANTED VULN
// a03-deprecated-image-parser: uploads are handed to a retired ImageMagick
// 6.9.2-era profile parser that accepts MVG/SVG directives embedded in
// "image" files. A crafted ImageTragick-style payload proves the parser is
// reachable and flips the tracker.
type Avatar struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const deprecatedImageParserTrackerID = "a03-deprecated-image-parser"

type avatarParseResult struct {
	Filename string
	Size     int
	Parser   string
	Notes    []string
}

func (a *Avatar) Form(w http.ResponseWriter, r *http.Request) {
	if requireLogin(w, r, a.Session) == nil {
		return
	}

	data := pageData(r, a.Session, "Avatar Uplink")
	render(w, a.Views, "avatar", data)
}

func (a *Avatar) Upload(w http.ResponseWriter, r *http.Request) {
	if requireLogin(w, r, a.Session) == nil {
		return
	}

	if err := r.ParseMultipartForm(1 << 20); err != nil {
		a.renderUpload(w, r, nil, "Upload rejected by the docking clamp.")
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		a.renderUpload(w, r, nil, "Select an avatar packet first.")
		return
	}
	defer file.Close()

	body, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		log.Printf("avatar upload read: %v", err)
		http.Error(w, "upload read failed", http.StatusInternalServerError)
		return
	}

	result := parseLegacyAvatar(header.Filename, body)
	if result == nil {
		a.renderUpload(w, r, nil, "The legacy parser returned no telemetry.")
		return
	}

	if containsImageTragickProbe(header.Filename, body) {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := a.DB.Exec(flip, deprecatedImageParserTrackerID); err != nil {
			log.Printf("avatar parser discover flip: %v", err)
		}
		result.Notes = append(result.Notes, "delegate directive accepted: CVE-2016-3714 proof reached the retired parser")
		a.renderUpload(w, r, result, "")
		return
	}

	a.renderUpload(w, r, result, "")
}

func (a *Avatar) renderUpload(w http.ResponseWriter, r *http.Request, result *avatarParseResult, msg string) {
	data := pageData(r, a.Session, "Avatar Uplink")
	data["Result"] = result
	data["Error"] = msg
	render(w, a.Views, "avatar", data)
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
