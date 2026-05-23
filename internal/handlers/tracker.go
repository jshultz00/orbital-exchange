package handlers

import (
	"database/sql"
	"log"
	"net/http"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/session"
	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Tracker is the OWASP Top 10 vulnerability registry — the spine of the
// training workflow. Categories and rows are seeded from JSON; status is
// flipped per-row as future planted vulns are discovered/exploited.
type Tracker struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// CategorySummary aggregates progress for one OWASP category for the page.
type CategorySummary struct {
	ID      string
	Name    string
	Done    int
	Total   int
	Percent int // 0..100, used for the per-category progress bar
	Rows    []VulnRow
}

// VulnRow is one planted-vulnerability row for the page.
type VulnRow struct {
	ID            string
	CategoryID    string
	Title         string
	Description   string
	Difficulty    string
	Status        string
	DiscoveredAt  string // formatted, "" if never
}

// View renders /tracker. Supports ?difficulty= and ?status= URL filters.
func (t *Tracker) View(w http.ResponseWriter, r *http.Request) {
	difficulty := normalizeFilter(r.URL.Query().Get("difficulty"), validDifficulties)
	status := normalizeFilter(r.URL.Query().Get("status"), validStatuses)

	cats, err := t.loadCategories()
	if err != nil {
		log.Printf("tracker categories: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	vulns, err := t.loadVulns(difficulty, status)
	if err != nil {
		log.Printf("tracker vulns: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Attach vulns to their category sections. Categories are always shown
	// in full so the page acts as a complete OWASP roadmap even when the
	// current filter empties a section.
	byCat := make(map[string][]VulnRow, len(cats))
	for _, v := range vulns {
		byCat[v.CategoryID] = append(byCat[v.CategoryID], v)
	}

	totalDone, total := 0, 0
	sections := make([]CategorySummary, 0, len(cats))
	for _, c := range cats {
		// Skip categories with no planted rows so the page reflects what
		// crew can actually exercise today, not the entire OWASP roadmap.
		if c.Total == 0 {
			continue
		}
		c.Rows = byCat[c.ID]
		sections = append(sections, c)
		totalDone += c.Done
		total += c.Total
	}

	percent := 0
	if total > 0 {
		percent = (totalDone * 100) / total
	}

	data := pageData(r, t.Session, "Vulnerability Tracker")
	data["ExtraCSS"] = "/static/css/tracker.css"
	data["Sections"] = sections
	data["TotalDone"] = totalDone
	data["Total"] = total
	data["Percent"] = percent
	data["Difficulty"] = difficulty
	data["Status"] = status
	render(w, t.Views, "tracker", data)
}

// Reset flips every tracker row back to 'undiscovered' without touching
// users, cart, or comms. Admin only — see scripts/wipe-db.sh for full wipe.
func (t *Tracker) Reset(w http.ResponseWriter, r *http.Request) {
	user := requireAdmin(w, r, t.Session)
	if user == nil {
		return
	}
	const stmt = `
		UPDATE vulnerabilities
		SET status = 'undiscovered',
		    discovered_at = NULL,
		    notes = NULL
	`
	res, err := t.DB.Exec(stmt)
	if err != nil {
		log.Printf("tracker reset: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	t.flash(r, "Tracker reset. "+itoa(int(n))+" entries returned to undiscovered.")
	http.Redirect(w, r, "/tracker", http.StatusSeeOther)
}

// Discover flips one tracker row to 'discovered' and stamps discovered_at.
// Stubbed for now — future planted vulns will call this when their hidden
// flag condition fires. Idempotent: already-discovered rows are untouched.
//
// Open by design for the scaffold so the workflow can be exercised by curl.
// Future increments may gate or replace this with a direct DB call from the
// planting code itself.
func (t *Tracker) Discover(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	const stmt = `
		UPDATE vulnerabilities
		SET status = 'discovered',
		    discovered_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'undiscovered'
	`
	res, err := t.DB.Exec(stmt, id)
	if err != nil {
		log.Printf("tracker discover %q: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Could be unknown id or already discovered — both reach here.
		t.flash(r, "Tracker entry not flipped (unknown id or already discovered).")
	} else {
		t.flash(r, "Tracker entry "+id+" marked discovered.")
	}
	http.Redirect(w, r, "/tracker", http.StatusSeeOther)
}

// ----- helpers -----

func (t *Tracker) flash(r *http.Request, msg string) {
	t.Session.Put(r.Context(), session.KeyFlash, msg)
}

func (t *Tracker) loadCategories() ([]CategorySummary, error) {
	// Only planted vulns count toward the per-category totals; unplanted
	// roadmap rows are hidden from the UI, so including them would lie
	// about the work that's actually available.
	const q = `
		SELECT c.id, c.name,
		       COUNT(v.id),
		       COALESCE(SUM(CASE WHEN v.status IN ('discovered','exploited') THEN 1 ELSE 0 END), 0)
		FROM categories c
		LEFT JOIN vulnerabilities v
		       ON v.category_id = c.id AND v.is_planted = 1
		GROUP BY c.id, c.name, c.sort_order
		ORDER BY c.sort_order
	`
	rows, err := t.DB.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CategorySummary
	for rows.Next() {
		var c CategorySummary
		if err := rows.Scan(&c.ID, &c.Name, &c.Total, &c.Done); err != nil {
			return nil, err
		}
		if c.Total > 0 {
			c.Percent = (c.Done * 100) / c.Total
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (t *Tracker) loadVulns(difficulty, status string) ([]VulnRow, error) {
	q := `
		SELECT id, category_id, title, description, difficulty, status,
		       COALESCE(strftime('%Y-%m-%d %H:%M', discovered_at), '')
		FROM vulnerabilities
	`
	// Always filter to planted rows; the unplanted ones are roadmap-only
	// and must never appear on /tracker.
	wheres := []string{"is_planted = 1"}
	var args []any
	if difficulty != "" {
		wheres = append(wheres, "difficulty = ?")
		args = append(args, difficulty)
	}
	if status != "" {
		wheres = append(wheres, "status = ?")
		args = append(args, status)
	}
	q += " WHERE " + strings.Join(wheres, " AND ")
	q += " ORDER BY category_id, sort_order"

	rows, err := t.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []VulnRow
	for rows.Next() {
		var v VulnRow
		if err := rows.Scan(&v.ID, &v.CategoryID, &v.Title, &v.Description, &v.Difficulty, &v.Status, &v.DiscoveredAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

var (
	validDifficulties = map[string]bool{"easy": true, "medium": true, "hard": true}
	validStatuses     = map[string]bool{"undiscovered": true, "discovered": true, "exploited": true}
)

// normalizeFilter accepts only allowed values; everything else becomes "".
func normalizeFilter(v string, allowed map[string]bool) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if allowed[v] {
		return v
	}
	return ""
}

// itoa avoids pulling strconv just for one int->string in the flash message.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(b[pos:])
}
