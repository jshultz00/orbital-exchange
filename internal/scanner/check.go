package scanner

import "context"

// Check is the interface every detection module implements. Keeping the
// surface this small means new checks are cheap to add: implement Run,
// register the constructor in cmd/vulnscope/main.go, done.
//
// LEARNING NOTE: This shape (one method, returns a slice of findings and an
// error) is the same one nuclei templates, semgrep rules, and most commercial
// scanners use internally. A check is allowed to return findings AND an error
// — partial results are valuable when a single endpoint times out mid-scan.
type Check interface {
	// ID is the dot-delimited check identifier, e.g. "a05.headers".
	// Used for --checks filtering on the CLI.
	ID() string

	// OWASPCategory is the top-level category, e.g. "A05".
	OWASPCategory() string

	// Description is one human-readable sentence shown in --list output.
	Description() string

	// Run executes the check against the supplied target. Implementations
	// MUST honour ctx cancellation (used by --timeout).
	Run(ctx context.Context, t *Target, deps Deps) ([]Finding, error)
}

// Deps bundles cross-cutting dependencies (HTTP client, logger) so individual
// Check implementations don't depend on package-level globals. Adding a new
// dependency means adding a field here, not threading it through every check.
type Deps struct {
	HTTP   HTTPDoer
	Logger Logger
}

// HTTPDoer is the minimal HTTP client surface a Check needs. Defining the
// interface here (rather than importing *http.Client) makes checks trivial
// to unit-test with a fake.
type HTTPDoer interface {
	Do(req *HTTPRequest) (*HTTPResponse, error)
}

// HTTPRequest / HTTPResponse are thin wrappers over net/http so tests don't
// have to spin up real servers. Defined in internal/httpclient.
type HTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

type HTTPResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	URL        string
}

// Logger is the minimal logging surface checks use. Implemented by anything
// that satisfies it; in practice we wire stdlib log.Logger.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}
