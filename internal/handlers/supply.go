package handlers

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/session"
	"github.com/jshultz00/orbital-exchange/internal/views"
)

// allocationRaceTrackerID is the planted A04 (Insecure Design) row flipped
// when the supply-drop claim gate is raced. The handler reads remaining,
// decides if there is stock, sleeps briefly, then writes — outside any
// transaction. Concurrent POSTs from the same crew member can each pass the
// "already claimed?" check and book multiple claims, and concurrent POSTs
// across crew can together push total claims past the drop's capacity.
const allocationRaceTrackerID = "a06-allocation-race"

// allocationGateWindow is the deliberate sleep between the gate's read and
// its writes. It widens the race window enough that a small concurrent
// burst from curl/xargs reliably wins, without making the page feel broken
// under normal use.
const allocationGateWindow = 75 * time.Millisecond

// Supply renders the "supply drop" page and processes claim submissions.
//
// Defensive baseline that is intentionally broken:
//   - No transaction wraps the read-then-write gate.
//   - The "one claim per crew" rule is enforced by a SELECT, not a unique
//     constraint, so two concurrent claims from the same user both insert.
//   - The "respect capacity" rule decrements remaining after the gate, so
//     concurrent claims across users can drive remaining negative.
type Supply struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// SupplyClaim is a row of supply_claims joined with users for the page view.
type SupplyClaim struct {
	Username  string
	ClaimedAt time.Time
}

// SupplyDropView is the page model for /bridge/supply-drop.
type SupplyDropView struct {
	ID          int64
	Slug        string
	Name        string
	Description string
	Capacity    int
	Remaining   int
	Active      bool
	Claims      []SupplyClaim
	YouClaimed  int
	TotalClaims int
}

// View renders GET /bridge/supply-drop with the current drop state.
func (s *Supply) View(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, s.Session)
	if user == nil {
		return
	}

	drop, err := s.activeDrop()
	if err != nil {
		log.Printf("supply drop lookup: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if drop != nil {
		claims, err := s.recentClaims(drop.ID)
		if err != nil {
			log.Printf("supply claims load: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		drop.Claims = claims
		drop.TotalClaims = len(claims)
		for _, c := range claims {
			if c.Username == user.Username {
				drop.YouClaimed++
			}
		}
	}

	data := pageData(r, s.Session, "Supply Drop")
	data["Drop"] = drop
	render(w, s.Views, "supply", data)
}

// Claim handles POST /bridge/supply-drop/claim. PLANTED VULN a06-allocation-race:
// the gate (a) looks up remaining stock and (b) checks the user has not already
// claimed, then sleeps, then writes — all outside a transaction. Two requests
// arriving in the window both pass the gate.
func (s *Supply) Claim(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, s.Session)
	if user == nil {
		return
	}

	drop, err := s.activeDrop()
	if err != nil {
		log.Printf("supply claim lookup: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if drop == nil {
		s.flash(r, "No active supply drop.")
		http.Redirect(w, r, "/bridge/supply-drop", http.StatusSeeOther)
		return
	}

	// Gate read 1: stock remaining.
	if drop.Remaining <= 0 {
		s.flash(r, "Drop exhausted.")
		http.Redirect(w, r, "/bridge/supply-drop", http.StatusSeeOther)
		return
	}

	// Gate read 2: has this crew member already claimed?
	var prior int
	err = s.DB.QueryRow(
		`SELECT COUNT(*) FROM supply_claims WHERE drop_id = ? AND user_id = ?`,
		drop.ID, user.ID,
	).Scan(&prior)
	if err != nil {
		log.Printf("supply claim prior count: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if prior > 0 {
		s.flash(r, "You have already claimed this drop.")
		http.Redirect(w, r, "/bridge/supply-drop", http.StatusSeeOther)
		return
	}

	// Deliberate gap between the gate read and the writes — widens the race
	// window enough that a small concurrent burst reliably oversubscribes.
	time.Sleep(allocationGateWindow)

	if _, err := s.DB.Exec(
		`INSERT INTO supply_claims (drop_id, user_id) VALUES (?, ?)`,
		drop.ID, user.ID,
	); err != nil {
		log.Printf("supply claim insert: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := s.DB.Exec(
		`UPDATE supply_drops SET remaining = remaining - 1 WHERE id = ?`,
		drop.ID,
	); err != nil {
		log.Printf("supply claim decrement: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.maybeFlipTracker(drop.ID, user.ID)

	s.flash(r, "Ration pack claimed.")
	http.Redirect(w, r, "/bridge/supply-drop", http.StatusSeeOther)
}

func (s *Supply) activeDrop() (*SupplyDropView, error) {
	const q = `
		SELECT id, slug, name, description, capacity, remaining, active
		FROM supply_drops
		WHERE active = 1
		ORDER BY id
		LIMIT 1
	`
	var (
		d      SupplyDropView
		active int
	)
	err := s.DB.QueryRow(q).Scan(&d.ID, &d.Slug, &d.Name, &d.Description, &d.Capacity, &d.Remaining, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d.Active = active == 1
	return &d, nil
}

func (s *Supply) recentClaims(dropID int64) ([]SupplyClaim, error) {
	const q = `
		SELECT u.username, sc.claimed_at
		FROM supply_claims sc
		JOIN users u ON u.id = sc.user_id
		WHERE sc.drop_id = ?
		ORDER BY sc.claimed_at, sc.id
	`
	rows, err := s.DB.Query(q, dropID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SupplyClaim
	for rows.Next() {
		var c SupplyClaim
		if err := rows.Scan(&c.Username, &c.ClaimedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// maybeFlipTracker flips the planted-vuln row when the race is observable:
// either this user now holds more than one claim against the drop, or total
// claims exceed the drop's capacity.
func (s *Supply) maybeFlipTracker(dropID, userID int64) {
	var (
		userClaims  int
		totalClaims int
		capacity    int
	)
	if err := s.DB.QueryRow(
		`SELECT COUNT(*) FROM supply_claims WHERE drop_id = ? AND user_id = ?`,
		dropID, userID,
	).Scan(&userClaims); err != nil {
		log.Printf("supply race detect user count: %v", err)
		return
	}
	if err := s.DB.QueryRow(
		`SELECT COUNT(*), (SELECT capacity FROM supply_drops WHERE id = ?)
		 FROM supply_claims WHERE drop_id = ?`,
		dropID, dropID,
	).Scan(&totalClaims, &capacity); err != nil {
		log.Printf("supply race detect total: %v", err)
		return
	}

	if userClaims <= 1 && totalClaims <= capacity {
		return
	}

	const flip = `
		UPDATE vulnerabilities
		SET status = 'discovered',
		    discovered_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'undiscovered'
	`
	if _, err := s.DB.Exec(flip, allocationRaceTrackerID); err != nil {
		log.Printf("supply allocation race discover flip: %v", err)
	}
}

func (s *Supply) flash(r *http.Request, msg string) {
	s.Session.Put(r.Context(), session.KeyFlash, msg)
}
