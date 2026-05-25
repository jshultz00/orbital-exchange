package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// LedgerCheck is the planted A10:2025 — Security Logging and Monitoring
// Failures handler for tracker row "a10-unchecked-exception-info-leak".
//
// In-fiction: a supply ledger entry verifier that checks whether a JSON
// payload is a valid ledger record. Out-of-fiction: the POST handler assumes
// the submitted JSON is well-formed and, when it isn't, writes the raw Go
// json.Unmarshal error (including internal struct field names and type
// expectations) directly into the HTTP response instead of a generic message.
//
// The Go error text for a type mismatch looks like:
//
//	json: cannot unmarshal string into Go struct field
//	ledgerEntry.qty of type int
//
// which reveals internal struct layout — field names, package paths, and
// expected types — enough to fingerprint the application and map its data
// model. A real server would log the technical error and return a generic
// "invalid payload" message instead.
type LedgerCheck struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const ledgerCheckTrackerID = "a10-unchecked-exception-info-leak"

// ledgerEntry is the typed struct the verifier decodes into.
// Field names and types are intentionally specific so that type-mismatch
// errors reveal them verbatim in the leaked error message.
type ledgerEntry struct {
	ItemCode  string `json:"item_code"`
	Qty       int    `json:"qty"`
	UnitPrice int    `json:"unit_price"`
	CycleID   int    `json:"cycle_id"`
	Verified  bool   `json:"verified"`
}

// Page handles GET /bridge/ledger-check — explains the endpoint.
func (l *LedgerCheck) Page(w http.ResponseWriter, r *http.Request) {
	if requireLogin(w, r, l.Session) == nil {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "=== Orbital Exchange :: Supply Ledger Verifier ===\n\n")
	fmt.Fprint(w, "POST /bridge/ledger-check with a JSON body to validate a ledger entry.\n\n")
	fmt.Fprint(w, "Expected fields: item_code (string), qty (int), unit_price (int),\n")
	fmt.Fprint(w, "                 cycle_id (int), verified (bool)\n\n")
	fmt.Fprint(w, "Example:\n")
	fmt.Fprint(w, `  curl -s -X POST /bridge/ledger-check \`)
	fmt.Fprint(w, "\n       -H 'Content-Type: application/json' \\\n")
	fmt.Fprint(w, `       -d '{"item_code":"OX-12","qty":4,"unit_price":50,"cycle_id":7,"verified":false}'`)
	fmt.Fprint(w, "\n")
}

// Verify handles POST /bridge/ledger-check. It reads a JSON body and attempts
// to decode it into a ledgerEntry. On type mismatch or structural error it
// writes the raw Go error into the response — the planted info leak.
func (l *LedgerCheck) Verify(w http.ResponseWriter, r *http.Request) {
	if requireLogin(w, r, l.Session) == nil {
		return
	}

	var entry ledgerEntry
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&entry); err != nil {
		// VULNERABLE BY DESIGN: the raw Go decode error is written into the
		// response. For type mismatches Go produces messages like:
		//   json: cannot unmarshal string into Go struct field
		//   ledgerEntry.qty of type int
		// which reveals internal field names and expected types. A hardened app
		// would log this error and return a generic "invalid payload" message.
		leaked := err.Error()
		log.Printf("ledger check decode: %v", leaked)

		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err2 := l.DB.Exec(flip, ledgerCheckTrackerID); err2 != nil {
			log.Printf("ledger check tracker flip: %v", err2)
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "ledger parse error: %s\n", leaked)
		return
	}

	var issues []string
	if strings.TrimSpace(entry.ItemCode) == "" {
		issues = append(issues, "item_code is required")
	}
	if entry.Qty <= 0 {
		issues = append(issues, "qty must be positive")
	}
	if entry.UnitPrice < 0 {
		issues = append(issues, "unit_price cannot be negative")
	}

	w.Header().Set("Content-Type", "application/json")
	if len(issues) > 0 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid":  false,
			"errors": issues,
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"valid":      true,
		"item_code":  entry.ItemCode,
		"qty":        entry.Qty,
		"unit_price": entry.UnitPrice,
		"cycle_id":   entry.CycleID,
		"verified":   entry.Verified,
	})
}
