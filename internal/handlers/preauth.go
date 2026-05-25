package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/session"
	"github.com/jshultz00/orbital-exchange/internal/views"
)

const unsafeDeserializationTrackerID = "a08-unsafe-deserialization"

// PreAuth handles the cargo pre-authorization token endpoint.
//
// PLANTED VULN a08-unsafe-deserialization: the redeem handler base64-decodes a
// JSON "pre-auth packet" from user input and trusts whatever Role and Operation
// fields the packet asserts — no signature, no cross-check against the session.
// A crew member who decodes their sample token, changes Role to
// "station_command" and Operation to "bulk_override", re-encodes, and submits
// gets admin-level authority over the cargo system.
type PreAuth struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// CargoPreAuthPacket is the struct that is serialized to/from base64+JSON.
// It is intentionally public so its shape is visible in the generated token.
type CargoPreAuthPacket struct {
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`      // "crew" or "station_command"
	Operation string `json:"operation"` // "standard_alloc" or "bulk_override"
	Credits   int    `json:"credits"`
	IssuedAt  string `json:"issued_at"`
}

type preAuthResult struct {
	Packet   *CargoPreAuthPacket
	Outcome  string
	Elevated bool
	Err      string
}

// Form renders GET /bridge/cargo-preauth.
func (p *PreAuth) Form(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, p.Session)
	if user == nil {
		return
	}
	data := pageData(r, p.Session, "Cargo Pre-Authorization")
	render(w, p.Views, "cargo_preauth", data)
}

// Token handles GET /bridge/cargo-preauth/token — generates a base64+JSON
// pre-auth packet for the current session user and returns it as plain text.
// The packet encodes role "crew" and operation "standard_alloc" so crew can
// inspect its structure and understand the format before tampering with it.
func (p *PreAuth) Token(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, p.Session)
	if user == nil {
		return
	}

	pkt := CargoPreAuthPacket{
		UserID:    user.ID,
		Username:  user.Username,
		Role:      "crew",
		Operation: "standard_alloc",
		Credits:   50,
		IssuedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	raw, err := json.MarshalIndent(pkt, "", "  ")
	if err != nil {
		http.Error(w, "token generation error", http.StatusInternalServerError)
		return
	}
	token := base64.StdEncoding.EncodeToString(raw)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, token)
}

// Redeem handles POST /bridge/cargo-preauth/redeem.
//
// PLANTED VULN: the packet is decoded and its Role/Operation fields are acted
// on directly. There is no HMAC, no session cross-check, and no server-side
// record of what was issued — whoever crafts a packet with
// Role="station_command" gets elevated authority regardless of their actual
// session privileges.
func (p *PreAuth) Redeem(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, p.Session)
	if user == nil {
		return
	}

	tokenStr := r.FormValue("preauth_token")
	data := pageData(r, p.Session, "Cargo Pre-Authorization")

	if tokenStr == "" {
		data["Result"] = &preAuthResult{Err: "No pre-authorization token supplied."}
		render(w, p.Views, "cargo_preauth", data)
		return
	}

	raw, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		data["Result"] = &preAuthResult{Err: "Token is not valid base64."}
		render(w, p.Views, "cargo_preauth", data)
		return
	}

	var pkt CargoPreAuthPacket
	if err := json.Unmarshal(raw, &pkt); err != nil {
		data["Result"] = &preAuthResult{Err: "Token payload could not be deserialized: " + err.Error()}
		render(w, p.Views, "cargo_preauth", data)
		return
	}

	result := &preAuthResult{Packet: &pkt}

	switch pkt.Role {
	case "station_command":
		// PLANTED VULN: this branch is reached whenever the deserialized Role
		// field says "station_command" — the session is never consulted.
		result.Elevated = true
		result.Outcome = fmt.Sprintf(
			"BULK OVERRIDE AUTHORIZED — %d credits allocated to cargo ledger under station command authority.",
			pkt.Credits,
		)

		// Insert an elevated manifest entry so the impact is observable.
		itemsJSON := fmt.Sprintf(
			`[{"name":"Bulk Override Allocation (station_command)","qty":1,"unit_price":%d}]`,
			pkt.Credits,
		)
		if _, dbErr := p.DB.Exec(
			`INSERT INTO manifests (user_id, summary, items_json, total_credits) VALUES (?, ?, ?, ?)`,
			user.ID, "Pre-Auth Bulk Override — "+pkt.Username, itemsJSON, pkt.Credits,
		); dbErr != nil {
			log.Printf("preauth manifest insert: %v", dbErr)
		}

		// Flip the tracker: session user is not admin but packet claimed station_command.
		if !user.IsAdmin {
			const flip = `
				UPDATE vulnerabilities
				SET status = 'discovered', discovered_at = CURRENT_TIMESTAMP
				WHERE id = ? AND status = 'undiscovered'
			`
			if _, dbErr := p.DB.Exec(flip, unsafeDeserializationTrackerID); dbErr != nil {
				log.Printf("preauth tracker flip: %v", dbErr)
			}
		}

	case "crew":
		result.Outcome = fmt.Sprintf(
			"Standard allocation confirmed for crew member %q — %d credits noted.",
			pkt.Username, pkt.Credits,
		)

	default:
		result.Err = fmt.Sprintf("Unknown role %q in packet.", pkt.Role)
	}

	data["Result"] = result
	render(w, p.Views, "cargo_preauth", data)
}

func (p *PreAuth) flash(r *http.Request, msg string) {
	p.Session.Put(r.Context(), session.KeyFlash, msg)
}
