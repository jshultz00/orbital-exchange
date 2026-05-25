package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/session"
	"github.com/jshultz00/orbital-exchange/internal/views"
)

const partialRollbackTrackerID = "a10-partial-rollback-on-error"

// CargoBundle is the planted A10:2025 handler for tracker row
// "a10-partial-rollback-on-error".
//
// In-fiction: a limited emergency cargo bundle allocation. Crew can claim one
// bundle pack while supplies last. The claim operation runs two writes:
//
//  1. INSERT a manifest for the crew member (the allocation receipt).
//  2. UPDATE cargo_bundles SET remaining = remaining - 1.
//
// No transaction wraps the pair. When remaining is already 0, the
// CHECK(remaining >= 0) constraint fires on step 2 and returns an error.
// Step 1's manifest has already been committed and is not rolled back —
// the crew member holds a manifest the bundle pool never counted.
type CargoBundle struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// CargoBundleView is the page model for /bridge/cargo-bundle.
type CargoBundleView struct {
	ID          int64
	Name        string
	Description string
	Remaining   int
	Active      bool
}

// Page handles GET /bridge/cargo-bundle.
func (cb *CargoBundle) Page(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, cb.Session)
	if user == nil {
		return
	}

	bundle, err := cb.activeBundle()
	if err != nil {
		log.Printf("cargo bundle page: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := pageData(r, cb.Session, "Cargo Bundle")
	data["Bundle"] = bundle
	render(w, cb.Views, "cargo_bundle", data)
}

// Claim handles POST /bridge/cargo-bundle/claim.
//
// PLANTED VULN a10-partial-rollback-on-error: the manifest INSERT (step 1)
// and the bundle decrement UPDATE (step 2) run outside any transaction. When
// remaining is 0, step 2's CHECK constraint fires and errors. Step 1's
// manifest persists — the crew member receives a valid manifest even though
// the bundle was already exhausted.
func (cb *CargoBundle) Claim(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, cb.Session)
	if user == nil {
		return
	}

	bundle, err := cb.activeBundle()
	if err != nil {
		log.Printf("cargo bundle claim lookup: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if bundle == nil || !bundle.Active {
		cb.flash(r, "No active cargo bundle.")
		http.Redirect(w, r, "/bridge/cargo-bundle", http.StatusSeeOther)
		return
	}

	// Step 1: insert the allocation manifest. This write is NOT wrapped in a
	// transaction — if step 2 later fails, this row will persist on disk.
	summary := fmt.Sprintf("Cargo bundle allocation — %s", bundle.Name)
	const itemsJSON = `[{"name":"Emergency cargo bundle","qty":1,"unit_price":0}]`
	res, err := cb.DB.Exec(
		`INSERT INTO manifests (user_id, summary, items_json, total_credits) VALUES (?, ?, ?, 0)`,
		user.ID, summary, itemsJSON,
	)
	if err != nil {
		log.Printf("cargo bundle manifest insert: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	mid, _ := res.LastInsertId()

	// Step 2: decrement the bundle pool. PLANTED VULN: when remaining is
	// already 0, the CHECK(remaining >= 0) constraint fires and this errors.
	// No rollback of the manifest inserted in step 1 follows — the system is
	// left in a partially-updated state.
	_, err = cb.DB.Exec(
		`UPDATE cargo_bundles SET remaining = remaining - 1 WHERE id = ?`,
		bundle.ID,
	)
	if err != nil {
		// VULNERABLE BY DESIGN: the manifest from step 1 is not rolled back.
		// The crew member gets a valid manifest # despite the pool being empty.
		log.Printf("cargo bundle decrement error (manifest %d persists): %v", mid, err)

		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, ferr := cb.DB.Exec(flip, partialRollbackTrackerID); ferr != nil {
			log.Printf("cargo bundle partial rollback tracker flip: %v", ferr)
		}

		cb.flash(r, fmt.Sprintf("Bundle allocation recorded. Manifest #%d.", mid))
		http.Redirect(w, r, fmt.Sprintf("/manifest/%d", mid), http.StatusSeeOther)
		return
	}

	cb.flash(r, fmt.Sprintf("Cargo bundle claimed. Manifest #%d.", mid))
	http.Redirect(w, r, fmt.Sprintf("/manifest/%d", mid), http.StatusSeeOther)
}

func (cb *CargoBundle) activeBundle() (*CargoBundleView, error) {
	const q = `
		SELECT id, name, description, remaining, active
		FROM cargo_bundles
		WHERE active = 1
		ORDER BY id
		LIMIT 1
	`
	var (
		b      CargoBundleView
		active int
	)
	err := cb.DB.QueryRow(q).Scan(&b.ID, &b.Name, &b.Description, &b.Remaining, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b.Active = active == 1
	return &b, nil
}

func (cb *CargoBundle) flash(r *http.Request, msg string) {
	cb.Session.Put(r.Context(), session.KeyFlash, msg)
}
