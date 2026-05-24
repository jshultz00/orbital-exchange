package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Beacon is the planted A01:2025 — Broken Access Control handler (SSRF, merged
// into A01 from A10:2021). The "bridge beacon scanner"
// fetches an arbitrary crew-supplied URL server-side and renders the response
// preview. No allowlist, no scheme restriction, no IP filtering — the whole
// point of the exercise.
//
// Tracker rows flipped on the way out:
//   - a01-beacon-scan-internal-service — any private / loopback / link-local target
//   - a01-beacon-cloud-metadata        — IMDS-style hosts (169.254.169.254, metadata.google.internal)
//   - a01-beacon-loopback-admin        — loopback target that surfaces admin-only content
type Beacon struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const (
	beaconInternalTrackerID = "a01-beacon-scan-internal-service"
	beaconMetadataTrackerID = "a01-beacon-cloud-metadata"
	beaconLoopbackTrackerID = "a01-beacon-loopback-admin"

	beaconMaxBytes  = 16 * 1024
	beaconHTTPLimit = 5 * time.Second
)

// Scan handles GET /bridge/beacon-scan. With no ?url= it renders the form;
// otherwise it fetches the URL server-side and shows the response preview.
func (b *Beacon) Scan(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, b.Session)
	if user == nil {
		return
	}

	target := strings.TrimSpace(r.URL.Query().Get("url"))
	data := pageData(r, b.Session, "Beacon Scanner")
	data["URL"] = target

	if target == "" {
		render(w, b.Views, "beacon", data)
		return
	}

	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		data["Error"] = "could not parse beacon target as a URL"
		render(w, b.Views, "beacon", data)
		return
	}

	body, status, headers, fetchErr := beaconFetch(target)
	if fetchErr != nil {
		data["Error"] = fetchErr.Error()
	} else {
		data["Status"] = status
		data["Headers"] = headers
		data["Body"] = string(body)
	}

	b.flipDiscoveries(parsed, body)
	render(w, b.Views, "beacon", data)
}

func beaconFetch(target string) ([]byte, int, string, error) {
	client := &http.Client{Timeout: beaconHTTPLimit}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "OrbitalExchange-BeaconScanner/1.0")
	// Some metadata services (GCP) require this header — leaving it on for parity
	// with the kind of misconfigured scanner this vuln models.
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, "", fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, beaconMaxBytes))

	var hdr strings.Builder
	for k, v := range resp.Header {
		fmt.Fprintf(&hdr, "%s: %s\n", k, strings.Join(v, ", "))
	}
	return body, resp.StatusCode, hdr.String(), nil
}

func (b *Beacon) flipDiscoveries(parsed *url.URL, body []byte) {
	host := parsed.Hostname()
	if host == "" {
		return
	}

	switch {
	case isCloudMetadataHost(host):
		b.flip(beaconMetadataTrackerID)
		b.flip(beaconInternalTrackerID)
	case isPrivateOrLoopback(host):
		b.flip(beaconInternalTrackerID)
		if isLoopback(host) && bodyLooksAdmin(body) {
			b.flip(beaconLoopbackTrackerID)
		}
	}
}

func (b *Beacon) flip(id string) {
	const q = `
		UPDATE vulnerabilities
		SET status = 'discovered',
		    discovered_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'undiscovered'
	`
	if _, err := b.DB.Exec(q, id); err != nil {
		log.Printf("beacon discover flip %s: %v", id, err)
	}
}

func isCloudMetadataHost(host string) bool {
	switch strings.ToLower(host) {
	case "169.254.169.254", "metadata.google.internal", "metadata.goog":
		return true
	}
	return false
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isPrivateOrLoopback(host string) bool {
	if isLoopback(host) {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// hostname — best-effort lookup; if it fails, treat as non-internal.
		ips, err := net.LookupIP(host)
		if err != nil {
			return false
		}
		for _, candidate := range ips {
			if candidate.IsLoopback() || candidate.IsPrivate() || candidate.IsLinkLocalUnicast() {
				return true
			}
		}
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// bodyLooksAdmin is a coarse heuristic: a loopback fetch that surfaces classic
// admin-panel strings counts as the "loopback admin" objective. Kept loose so
// crew can point the scanner at /command, /debug, etc.
func bodyLooksAdmin(body []byte) bool {
	lower := strings.ToLower(string(body))
	for _, s := range []string{"station command", "diagnostics", "default credentials", "debug", "bridge dashboard"} {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
