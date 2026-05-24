package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"strconv"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Telemetry is the planted A05 (Security Misconfiguration) entry point for
// "a02-verbose-stack-traces". The route deliberately offers a knob the crew
// can wiggle into a runtime panic; the global Recover middleware then dumps
// the full Go stack trace (with file paths and line numbers) straight into
// the HTTP response. Together they teach the lesson that production servers
// should NEVER ship unfiltered stack traces back to clients.
type Telemetry struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const verboseStackTrackerID = "a02-verbose-stack-traces"

// Cycle handles GET /telemetry. With no ?cycle= it explains the endpoint.
// With a valid integer it returns a small summary. With a non-integer (e.g.
// "?cycle=overload") it panics — the recovery middleware then reveals the
// stack trace.
func (t *Telemetry) Cycle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("cycle")
	if q == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "telemetry: pass ?cycle=<integer> to read a station cycle snapshot.")
		return
	}

	// Deliberately panics on bad input — the recovery middleware exposes the
	// stack trace, which is the whole exercise.
	n, err := strconv.Atoi(q)
	if err != nil {
		panic(fmt.Sprintf("telemetry: invalid cycle %q: %v", q, err))
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "cycle %d: nominal\n", n)
}

// Recover is the global middleware that catches panics in any handler and
// writes a verbose stack trace (plus request metadata) to the response.
// Wrap this around the whole mux. Flips the a02-verbose-stack-traces tracker
// row the first time it catches anything.
func Recover(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}

			// Flip the tracker row on first panic.
			const flip = `
				UPDATE vulnerabilities
				SET status = 'discovered',
				    discovered_at = CURRENT_TIMESTAMP
				WHERE id = ? AND status = 'undiscovered'
			`
			if _, err := db.Exec(flip, verboseStackTrackerID); err != nil {
				log.Printf("verbose stack discover flip: %v", err)
			}

			stack := debug.Stack()
			log.Printf("recovered panic on %s %s: %v\n%s", r.Method, r.URL.Path, rec, stack)

			// VULNERABLE BY DESIGN: the full stack trace, file paths, and
			// request details land in the response body. A production app
			// would emit a generic 500 here and log the trace internally.
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "=== Orbital Exchange :: Unhandled Telemetry Fault ===")
			fmt.Fprintf(w, "request   : %s %s\n", r.Method, r.URL.String())
			fmt.Fprintf(w, "remote    : %s\n", r.RemoteAddr)
			fmt.Fprintf(w, "user-agent: %s\n\n", r.UserAgent())
			fmt.Fprintf(w, "panic     : %v\n\n", rec)
			fmt.Fprintln(w, "[goroutine stack]")
			_, _ = w.Write(stack)
		}()
		next.ServeHTTP(w, r)
	})
}
