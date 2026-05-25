package handlers

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Comms handles the station comms log — a public feedback / message board.
// Anonymous submissions are allowed by design; the comms log is the planned
// home of several A03 (XSS, log-injection) planted vulns.
//
// Defensive baseline:
//   - html/template auto-escapes user input on render.
//   - Body and author lengths bounded.
//   - user_id populated from session when authed, NULL otherwise.
type Comms struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// CommsEntry is one row of the comms log for rendering.
type CommsEntry struct {
	ID        int64
	Author    string
	Body      template.HTML // PLANTED VULN a05-comms-stored-xss: rendered unescaped
	Format    string        // 'raw' or 'markdown'
	CreatedAt string        // pre-formatted in SQL for simplicity
	FromCrew  bool          // true if user_id is non-NULL — UI styles authed entries
}

const vulnerableMarkdownTrackerID = "a03-vulnerable-markdown"

// List renders /comms.
func (c *Comms) List(w http.ResponseWriter, r *http.Request) {
	const q = `
		SELECT id, author, body, format,
		       strftime('%Y-%m-%d %H:%M', created_at) AS created_at,
		       user_id IS NOT NULL AS from_crew
		FROM comms_entries
		ORDER BY created_at DESC
		LIMIT 100
	`
	rows, err := c.DB.Query(q)
	if err != nil {
		log.Printf("comms list query: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var entries []CommsEntry
	for rows.Next() {
		var e CommsEntry
		var bodyStr string
		if err := rows.Scan(&e.ID, &e.Author, &bodyStr, &e.Format, &e.CreatedAt, &e.FromCrew); err != nil {
			log.Printf("comms list scan: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// PLANTED VULNS: 'raw' renders unescaped HTML (a05-comms-stored-xss);
		// 'markdown' renders via the in-house markdown sanitizer that strips
		// <script> tags but allows javascript: URL bypasses
		// (a03-vulnerable-markdown).
		if e.Format == "markdown" {
			e.Body = renderVulnerableMarkdown(bodyStr)
		} else {
			e.Body = template.HTML(bodyStr)
		}
		entries = append(entries, e)
	}

	data := pageData(r, c.Session, "Comms Log")
	data["Entries"] = entries
	render(w, c.Views, "comms", data)
}

// Submit appends a new comms entry. Both anonymous and authed crew may post.
func (c *Comms) Submit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	body := trimMax(r.PostFormValue("body"), 2000)
	if body == "" {
		http.Redirect(w, r, "/comms", http.StatusSeeOther)
		return
	}
	format := r.PostFormValue("format")
	if format != "markdown" {
		format = "raw"
	}

	user := currentUser(r, c.Session)

	// Author: prefer authed username, fall back to submitted name, then "Anonymous Crew".
	var (
		author string
		userID any // sql nullable
	)
	if user != nil {
		author = user.Username
		userID = user.ID
	} else {
		author = trimMax(r.PostFormValue("author"), 64)
		if author == "" {
			author = "Anonymous Crew"
		}
		userID = nil
	}

	// PLANTED VULN a09-log-injection-newline: the author field from user input
	// lands in the log verbatim. A newline character in the author value splits
	// the log line, allowing an attacker to forge the appearance of additional
	// log entries. A real app would strip or escape control characters before
	// logging user-supplied strings.
	log.Printf("comms: received transmission from %s (format=%s)", author, format)

	if _, err := c.DB.Exec(
		`INSERT INTO comms_entries (user_id, author, body, format) VALUES (?, ?, ?, ?)`,
		userID, author, body, format,
	); err != nil {
		log.Printf("comms submit insert: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	const flip = `
		UPDATE vulnerabilities
		SET status = 'discovered',
		    discovered_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'undiscovered'
	`
	// Log-injection detection: the author was logged verbatim above. If it
	// contains a newline or carriage return, an attacker injected a fake log
	// line into the server log. PLANTED VULN a09-log-injection-newline.
	if strings.ContainsAny(author, "\n\r") {
		if _, err := c.DB.Exec(flip, "a09-log-injection-newline"); err != nil {
			log.Printf("comms log-inject discover flip: %v", err)
		}
	}
	// XSS detection (raw rendering path): look for script tags, event
	// handlers, or other markup. PLANTED VULN a05-comms-stored-xss.
	if format == "raw" && detectXSSPattern(body) {
		if _, err := c.DB.Exec(flip, "a05-comms-stored-xss"); err != nil {
			log.Printf("comms XSS discover flip: %v", err)
		}
	}
	// Markdown-renderer bypass detection. PLANTED VULN a03-vulnerable-markdown:
	// the in-house renderer strips <script> tags but lets javascript: URLs and
	// event-handler attributes through the link/image syntax.
	if format == "markdown" && detectMarkdownBypass(body) {
		if _, err := c.DB.Exec(flip, vulnerableMarkdownTrackerID); err != nil {
			log.Printf("comms markdown discover flip: %v", err)
		}
	}

	http.Redirect(w, r, "/comms", http.StatusSeeOther)
}

// Delete removes a comms entry. Admin-only. PLANTED VULN
// a09-comms-log-silent-delete: the destructive action writes no audit row —
// the entry simply vanishes. The tracker flips on the first such delete to
// surface the missing logging.
func (c *Comms) Delete(w http.ResponseWriter, r *http.Request) {
	user := requireAdmin(w, r, c.Session)
	if user == nil {
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	res, err := c.DB.Exec(`DELETE FROM comms_entries WHERE id = ?`, id)
	if err != nil {
		log.Printf("comms delete: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Intentionally NO audit log insert here. That gap is the lesson.

	if n, _ := res.RowsAffected(); n > 0 {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := c.DB.Exec(flip, "a09-comms-log-silent-delete"); err != nil {
			log.Printf("comms silent-delete discover flip: %v", err)
		}
	}

	http.Redirect(w, r, "/comms", http.StatusSeeOther)
}

// scriptTagRE strips <script>...</script> blocks (and bare opening tags)
// from input, case-insensitively. The in-house markdown sanitizer treats
// this as "enough" — but it doesn't validate URL schemes in the link/image
// syntax that follows, so javascript: links and onerror handlers planted
// through image syntax escape the gate. PLANTED VULN a03-vulnerable-markdown.
var (
	scriptTagRE   = regexp.MustCompile(`(?is)<\s*script.*?</\s*script\s*>|<\s*script[^>]*>`)
	mdBoldRE      = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdItalicRE    = regexp.MustCompile(`\*([^*]+)\*`)
	mdImageRE     = regexp.MustCompile(`!\[([^\]]*)\]\(([^)]+)\)`)
	mdLinkRE      = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	mdCodeRE      = regexp.MustCompile("`([^`]+)`")
)

// renderVulnerableMarkdown is the station's in-house markdown renderer.
// It strips <script> tags (its sole sanitization) and then expands
// **bold**, *italic*, `code`, ![alt](url), and [text](url). It does NOT
// validate URL schemes — javascript: and data: links slip through, and the
// image syntax preserves whatever the author crammed into the URL field,
// including event-handler attributes. This mirrors a class of real-world
// markdown CVEs (e.g. CVE-2018-3717 in marked, CVE-2021-44906 around
// markdown-it sanitizer bypasses).
func renderVulnerableMarkdown(s string) template.HTML {
	out := scriptTagRE.ReplaceAllString(s, "")
	out = mdImageRE.ReplaceAllString(out, `<img src="$2" alt="$1">`)
	out = mdLinkRE.ReplaceAllString(out, `<a href="$2">$1</a>`)
	out = mdBoldRE.ReplaceAllString(out, `<strong>$1</strong>`)
	out = mdItalicRE.ReplaceAllString(out, `<em>$1</em>`)
	out = mdCodeRE.ReplaceAllString(out, `<code>$1</code>`)
	return template.HTML(out)
}

// detectMarkdownBypass returns true when the input shows a known sanitizer
// bypass: a markdown link/image carrying a javascript:/data: URL, or an
// image URL field stuffed with an event-handler attribute.
func detectMarkdownBypass(s string) bool {
	for _, m := range mdLinkRE.FindAllStringSubmatch(s, -1) {
		if isDangerousURL(m[2]) {
			return true
		}
	}
	for _, m := range mdImageRE.FindAllStringSubmatch(s, -1) {
		if isDangerousURL(m[2]) {
			return true
		}
		lower := strings.ToLower(m[2])
		if strings.Contains(lower, "onerror=") || strings.Contains(lower, "onload=") {
			return true
		}
	}
	return false
}

func isDangerousURL(u string) bool {
	lower := strings.ToLower(strings.TrimSpace(u))
	return strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "data:text/html")
}

// detectXSSPattern checks for common XSS payloads in a string.
func detectXSSPattern(s string) bool {
	lower := strings.ToLower(s)
	patterns := []string{
		"<script",
		"javascript:",
		"onerror=",
		"onload=",
		"onclick=",
		"onmouseover=",
		"<iframe",
		"<object",
		"<embed",
		"<img ",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
