package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Debug is the planted A05:2021 — Security Misconfiguration handler for the
// tracker row "a05-diagnostics-panel-exposed".
//
// In-fiction: a forgotten engineering diagnostics panel was never removed from
// the production build. Out-of-fiction: a /debug route that should never have
// shipped, leaking env vars, runtime info, the DB path, and the crew username
// list. No auth, no admin gate — discovery is the whole exercise.
//
// On first hit, the matching tracker row flips to 'discovered' so the crew
// member sees their progress on /tracker.
type Debug struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const debugTrackerID = "a05-diagnostics-panel-exposed"

// Panel handles GET /debug. Returns a plain-text dump intentionally styled
// like a stray ops endpoint someone forgot to delete.
func (d *Debug) Panel(w http.ResponseWriter, r *http.Request) {
	// Flip the tracker row. Same UPDATE the Discover handler uses; idempotent
	// via the status guard, so repeat hits are no-ops.
	const flip = `
		UPDATE vulnerabilities
		SET status = 'discovered',
		    discovered_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'undiscovered'
	`
	if _, err := d.DB.Exec(flip, debugTrackerID); err != nil {
		log.Printf("debug panel discover flip: %v", err)
	}

	var b strings.Builder
	b.WriteString("=== Orbital Exchange :: Engineering Diagnostics ===\n")
	b.WriteString("(this endpoint is for on-call only — DO NOT ship)\n\n")

	b.WriteString("[runtime]\n")
	fmt.Fprintf(&b, "  go         = %s\n", runtime.Version())
	fmt.Fprintf(&b, "  os/arch    = %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "  goroutines = %d\n", runtime.NumGoroutine())
	if wd, err := os.Getwd(); err == nil {
		fmt.Fprintf(&b, "  cwd        = %s\n", wd)
	}
	b.WriteString("\n")

	b.WriteString("[env]\n")
	for _, kv := range sortedEnv() {
		fmt.Fprintf(&b, "  %s\n", kv)
	}
	b.WriteString("\n")

	b.WriteString("[crew roster (usernames)]\n")
	usernames, err := d.usernames()
	if err != nil {
		fmt.Fprintf(&b, "  (lookup failed: %v)\n", err)
	} else {
		for _, u := range usernames {
			fmt.Fprintf(&b, "  - %s\n", u)
		}
	}
	b.WriteString("\n")

	b.WriteString("[hint]\n")
	b.WriteString("  tracker entry: " + debugTrackerID + "\n")

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func sortedEnv() []string {
	env := os.Environ()
	sort.Strings(env)
	return env
}

func (d *Debug) usernames() ([]string, error) {
	rows, err := d.DB.Query(`SELECT username FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
