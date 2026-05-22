package scanner

import (
	"fmt"
	"net/url"
	"strings"
)

// Target describes the system under test. Per 00-scope.md §3, vulnscope is
// scoped to a single locally hosted Juice Shop instance; Target therefore
// models exactly one base URL plus optional credentials for authenticated
// checks (e.g. A01 IDOR, which needs two real sessions).
type Target struct {
	// BaseURL is the application root, e.g. "http://localhost:3000".
	// Trailing slashes are stripped.
	BaseURL string

	// UserAgent is sent on every request so the target's logs unambiguously
	// show which traffic came from this tool. Defaults to "vulnscope/<version>".
	UserAgent string

	// RateLimit caps requests per second. 0 means no limit.
	// LEARNING NOTE: even though Juice Shop is local and disposable, a rate
	// limiter is wired in from day one because every real engagement has one,
	// and forgetting to add it later is how scanners DoS production by accident.
	RateLimit float64
}

// NewTarget validates and normalises a base URL into a Target.
func NewTarget(raw string) (*Target, error) {
	if raw == "" {
		return nil, fmt.Errorf("target URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse target %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("target scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("target %q has no host", raw)
	}
	return &Target{
		BaseURL: strings.TrimRight(u.String(), "/"),
	}, nil
}

// URL joins a path onto the target base URL. The path may start with "/" or not.
func (t *Target) URL(path string) string {
	if path == "" {
		return t.BaseURL
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return t.BaseURL + path
}
