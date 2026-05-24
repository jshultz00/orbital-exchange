package handlers

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// CommsBeacon is the planted A04:2025 — Cryptographic Failures handler for
// a04-comms-beacon-cipher. The station broadcasts outbound "comms beacons"
// signed by a homegrown MAC routine and a short shared secret. The page
// publishes the spec alongside recent beacons so any crew member can
// independently verify authenticity — and brute-force the secret offline.
type CommsBeacon struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const (
	commsBeaconTrackerID = "a04-comms-beacon-cipher"

	// PLANTED VULN a04-comms-beacon-cipher: a short, guessable shared
	// secret used to MAC every outbound beacon. Combined with the
	// published, non-HMAC signing routine below, the whole scheme falls
	// to an offline dictionary or sub-second brute force.
	commsBeaconSecret = "orbit"
)

type commsBeaconSample struct {
	Sequence  int
	Timestamp string
	Message   string
	Signature string
}

var commsBeaconSamples = func() []commsBeaconSample {
	raw := []struct {
		Seq int
		TS  string
		Msg string
	}{
		{1, "1735689600", "airlock-cycle-complete"},
		{2, "1735689712", "o2-nominal"},
		{3, "1735689824", "docking-ack:vessel-7"},
		{4, "1735689940", "thermal-loop-stable"},
	}
	out := make([]commsBeaconSample, len(raw))
	for i, r := range raw {
		out[i] = commsBeaconSample{
			Sequence:  r.Seq,
			Timestamp: r.TS,
			Message:   r.Msg,
			Signature: signCommsBeacon(commsBeaconSecret, r.TS, r.Msg),
		}
	}
	return out
}()

// signCommsBeacon is the station's outbound MAC routine. Intentionally not
// HMAC: XOR of two SHA-1 digests with the secret moved between the head
// and tail of the input, truncated to 80 bits. The spec is published on
// the beacon page so verifiers (and attackers) can reproduce it.
func signCommsBeacon(secret, ts, msg string) string {
	a := sha1.Sum([]byte(secret + "|" + ts + "|" + msg))
	b := sha1.Sum([]byte(ts + "|" + msg + "|" + secret))
	out := make([]byte, 10)
	for i := 0; i < 10; i++ {
		out[i] = a[i] ^ b[i]
	}
	return hex.EncodeToString(out)
}

// Page renders GET /bridge/comms-beacon — the public beacon log and verifier.
func (c *CommsBeacon) Page(w http.ResponseWriter, r *http.Request) {
	data := pageData(r, c.Session, "Comms Beacon Log")
	data["Beacons"] = commsBeaconSamples
	render(w, c.Views, "comms_beacon", data)
}

// Verify accepts a candidate secret. If signing any published beacon with
// the candidate reproduces the stored signature, the tracker flips.
func (c *CommsBeacon) Verify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	candidate := r.PostFormValue("secret")

	data := pageData(r, c.Session, "Comms Beacon Log")
	data["Beacons"] = commsBeaconSamples
	data["AttemptSecret"] = candidate

	matched := false
	if candidate != "" {
		for _, b := range commsBeaconSamples {
			if signCommsBeacon(candidate, b.Timestamp, b.Message) == b.Signature {
				matched = true
				break
			}
		}
	}

	if matched {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := c.DB.Exec(flip, commsBeaconTrackerID); err != nil {
			log.Printf("comms-beacon discover flip: %v", err)
		}
		data["VerifySuccess"] = "Signature reproduced. Shared beacon secret confirmed."
	} else if candidate != "" {
		data["VerifyError"] = "Signature mismatch. That secret does not reproduce the published MAC."
	}

	render(w, c.Views, "comms_beacon", data)
}
