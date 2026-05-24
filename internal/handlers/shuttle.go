package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Shuttle handles the station's "shuttle pass" — a JWT-style token that
// asserts who you are and whether you carry Command privileges. PLANTED VULN
// a03-known-cve-jwt: the verifier honors the token's own `alg` header. A
// crafted token with `alg: none` (a well-publicized class of JWT library
// bugs, e.g. CVE-2015-9235) bypasses signature verification entirely, so
// any payload — including {admin: true} — is accepted.
type Shuttle struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const (
	shuttleJWTTrackerID = "a03-known-cve-jwt"

	// shuttleJWTSecret is the HS256 signing key. Publishing it here matters
	// less than you'd think: the alg=none bypass means an attacker doesn't
	// need the key at all.
	shuttleJWTSecret = "orbit-shuttle-hs256-secret"
)

type shuttleClaims struct {
	Sub   string `json:"sub"`
	Admin bool   `json:"admin"`
	Iat   int64  `json:"iat"`
}

type shuttleHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Page renders GET /shuttle. Logged-in crew see a freshly-minted shuttle pass
// for their account. The verifier form is always shown.
func (s *Shuttle) Page(w http.ResponseWriter, r *http.Request) {
	data := pageData(r, s.Session, "Shuttle Pass")

	user := currentUser(r, s.Session)
	if user != nil {
		claims := shuttleClaims{Sub: user.Username, Admin: user.IsAdmin, Iat: time.Now().Unix()}
		token, err := mintShuttleJWT(claims)
		if err != nil {
			log.Printf("shuttle mint: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		data["Token"] = token
		data["Claims"] = claims
	}
	render(w, s.Views, "shuttle", data)
}

// Verify handles POST /shuttle/verify — accepts a candidate pass, parses it,
// reports the claims if it "verifies." PLANTED VULN: alg=none is honored.
func (s *Shuttle) Verify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	candidate := strings.TrimSpace(r.PostFormValue("token"))

	data := pageData(r, s.Session, "Shuttle Pass")
	user := currentUser(r, s.Session)
	if user != nil {
		claims := shuttleClaims{Sub: user.Username, Admin: user.IsAdmin, Iat: time.Now().Unix()}
		if tok, err := mintShuttleJWT(claims); err == nil {
			data["Token"] = tok
			data["Claims"] = claims
		}
	}
	data["AttemptToken"] = candidate

	claims, alg, err := verifyShuttleJWT(candidate)
	if err != nil {
		data["VerifyError"] = "Pass rejected: " + err.Error()
		render(w, s.Views, "shuttle", data)
		return
	}

	data["VerifiedClaims"] = claims
	data["VerifiedAlg"] = alg

	// Tracker flip: alg=none accepted AND the payload would grant the holder
	// privileges they do not actually carry. The simplest signal: the token
	// claims admin AND uses alg=none.
	if strings.EqualFold(alg, "none") && claims.Admin {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := s.DB.Exec(flip, shuttleJWTTrackerID); err != nil {
			log.Printf("shuttle jwt discover flip: %v", err)
		}
		data["VerifySuccess"] = "Pass accepted as STATION COMMAND. (alg=none honored.)"
	} else {
		data["VerifySuccess"] = fmt.Sprintf("Pass accepted for %s (admin=%v, alg=%s).", claims.Sub, claims.Admin, alg)
	}

	render(w, s.Views, "shuttle", data)
}

// mintShuttleJWT builds an HS256-signed JWT for the given claims.
func mintShuttleJWT(c shuttleClaims) (string, error) {
	header := shuttleHeader{Alg: "HS256", Typ: "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(pb)
	mac := hmac.New(sha256.New, []byte(shuttleJWTSecret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + enc.EncodeToString(mac.Sum(nil)), nil
}

// verifyShuttleJWT parses a JWT-style token. PLANTED VULN: when the header
// alg is "none" (case-insensitive), signature verification is skipped and the
// payload is accepted as-is.
func verifyShuttleJWT(token string) (shuttleClaims, string, error) {
	var zero shuttleClaims
	parts := strings.Split(token, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return zero, "", fmt.Errorf("malformed token")
	}
	enc := base64.RawURLEncoding
	hraw, err := enc.DecodeString(parts[0])
	if err != nil {
		return zero, "", fmt.Errorf("bad header encoding")
	}
	var h shuttleHeader
	if err := json.Unmarshal(hraw, &h); err != nil {
		return zero, "", fmt.Errorf("bad header json")
	}
	praw, err := enc.DecodeString(parts[1])
	if err != nil {
		return zero, "", fmt.Errorf("bad payload encoding")
	}
	var c shuttleClaims
	if err := json.Unmarshal(praw, &c); err != nil {
		return zero, "", fmt.Errorf("bad payload json")
	}

	switch strings.ToLower(h.Alg) {
	case "none":
		// PLANTED VULN: signature not checked.
		return c, h.Alg, nil
	case "hs256":
		if len(parts) != 3 {
			return zero, "", fmt.Errorf("missing signature")
		}
		sig, err := enc.DecodeString(parts[2])
		if err != nil {
			return zero, "", fmt.Errorf("bad signature encoding")
		}
		mac := hmac.New(sha256.New, []byte(shuttleJWTSecret))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return zero, "", fmt.Errorf("signature mismatch")
		}
		return c, h.Alg, nil
	default:
		return zero, "", fmt.Errorf("unsupported algorithm")
	}
}
