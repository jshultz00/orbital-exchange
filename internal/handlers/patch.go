package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

const updateChannelTrackerID = "a08-update-channel-unverified"

// officialPatchURL is the canonical patch distribution endpoint published by
// Station Command. Intentionally unreachable so crew must override it.
const officialPatchURL = "https://patch-dist.station-command.internal/v1/manifest.json"

// officialPatchBody is the authoritative manifest payload Station Command
// distributes. Its SHA-256 is pre-published so a verifying client could check
// integrity — but the apply endpoint never does.
var officialPatchBody = func() []byte {
	b, _ := json.MarshalIndent(map[string]any{
		"version":  "1.4.2",
		"released": "2025-10-01T00:00:00Z",
		"modules":  []string{"hull-integrity", "life-support", "docking-control", "comms-relay"},
		"notes":    "Routine maintenance cycle. Addresses thermal-loop calibration drift.",
	}, "", "  ")
	return b
}()

// officialPatchHash is the SHA-256 of officialPatchBody, published on the
// page so crew can verify a fetch — the apply endpoint skips this check.
var officialPatchHash = func() string {
	h := sha256.Sum256(officialPatchBody)
	return hex.EncodeToString(h[:])
}()

// PatchChannel is the planted A08:2021 — Software and Data Integrity Failures
// handler for a08-update-channel-unverified (CWE-494).
//
// PLANTED VULN: the apply endpoint fetches whatever URL crew supplies, skips
// the SHA-256 integrity check, and marks the patch "applied" regardless.
// Crew who override the patch URL with any URL they control slip arbitrary
// content through the update channel undetected.
type PatchChannel struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

type patchFetchResult struct {
	PatchURL     string
	StatusCode   int
	BodySnip     string
	ReceivedHash string
	ExpectedHash string
	HashMatch    bool
	Applied      bool
	Err          string
}

// Page renders GET /bridge/patch-channel.
func (p *PatchChannel) Page(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, p.Session)
	if user == nil {
		return
	}
	data := pageData(r, p.Session, "Patch Channel")
	data["OfficialURL"] = officialPatchURL
	data["ExpectedHash"] = officialPatchHash
	data["OfficialManifest"] = string(officialPatchBody)
	render(w, p.Views, "patch_channel", data)
}

// Apply handles POST /bridge/patch-channel/apply.
//
// PLANTED VULN: fetches patch_url and installs the result unconditionally.
// The received SHA-256 is displayed for reference but never gates the apply
// step. A hash mismatch means forged content reached the station — the tracker
// flips to record the discovery.
func (p *PatchChannel) Apply(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, p.Session)
	if user == nil {
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	patchURL := strings.TrimSpace(r.PostFormValue("patch_url"))
	if patchURL == "" {
		patchURL = officialPatchURL
	}

	data := pageData(r, p.Session, "Patch Channel")
	data["OfficialURL"] = officialPatchURL
	data["ExpectedHash"] = officialPatchHash
	data["OfficialManifest"] = string(officialPatchBody)

	result := &patchFetchResult{PatchURL: patchURL}

	parsed, err := url.Parse(patchURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		result.Err = "could not parse patch URL — supply a full URL including scheme"
		data["Result"] = result
		render(w, p.Views, "patch_channel", data)
		return
	}

	body, status, fetchErr := patchChannelFetch(patchURL)
	if fetchErr != nil {
		result.Err = "fetch error: " + fetchErr.Error()
		data["Result"] = result
		render(w, p.Views, "patch_channel", data)
		return
	}

	result.StatusCode = status
	if len(body) > 1024 {
		result.BodySnip = string(body[:1024]) + "\n[truncated]"
	} else {
		result.BodySnip = string(body)
	}

	h := sha256.Sum256(body)
	result.ReceivedHash = hex.EncodeToString(h[:])
	result.ExpectedHash = officialPatchHash
	result.HashMatch = result.ReceivedHash == result.ExpectedHash

	// PLANTED VULN: patch is applied regardless of hash match.
	result.Applied = true

	if !result.HashMatch {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered', discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := p.DB.Exec(flip, updateChannelTrackerID); err != nil {
			log.Printf("patch-channel tracker flip: %v", err)
		}
	}

	data["Result"] = result
	render(w, p.Views, "patch_channel", data)
}

func patchChannelFetch(target string) ([]byte, int, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	return body, resp.StatusCode, nil
}
