// Package scanner defines the core types every detection module shares:
// the Check interface that all checks implement, the Finding struct that
// every check emits, and the Target that describes the system under test.
//
// LEARNING NOTE: in a real pentest, every reportable issue is normalised to
// the same shape — title, severity, evidence, remediation — so that downstream
// tooling (report generators, ticket systems, SIEMs) does not need to know
// which check produced it. That normalisation is what this package provides.
package scanner

import (
	"fmt"
	"strings"
	"time"
)

// Severity is a human-readable severity band derived from the CVSS base score.
//
// CVSS v3.1 score bands per FIRST.org:
//
//	0.0        -> Informational
//	0.1 - 3.9  -> Low
//	4.0 - 6.9  -> Medium
//	7.0 - 8.9  -> High
//	9.0 - 10.0 -> Critical
type Severity string

const (
	SeverityInfo     Severity = "Informational"
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)

// SeverityFromCVSS maps a CVSS v3.1 base score to its severity band.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0.0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// Finding is one issue produced by a Check. Every field is intentionally
// non-optional from a reporting perspective: a Finding without evidence or a
// repro step is not a finding, it is speculation.
type Finding struct {
	// ID is a stable identifier of the form "VS-<CHECK>-<NUM>", e.g. "VS-A05-001".
	// Stable IDs let writeups in 02-findings/ cross-reference the scanner output.
	ID string `json:"id"`

	// OWASPCategory is the top-level OWASP Top 10 (2021) category, e.g. "A05".
	OWASPCategory string `json:"owasp_category"`

	// CheckID identifies the specific check that produced the finding,
	// e.g. "a05.headers.missing-csp". Lower-case, dot-delimited.
	CheckID string `json:"check_id"`

	// Title is a short, finding-style sentence, e.g.
	// "Missing Content-Security-Policy header".
	Title string `json:"title"`

	// Description explains what the vulnerability is and why it matters,
	// independent of this specific occurrence.
	Description string `json:"description"`

	// Severity is the band derived from the CVSS base score.
	Severity Severity `json:"severity"`

	// CVSS is the full v3.1 base vector string, e.g.
	// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N".
	// Recording the full vector (not just the score) is consultant-grade practice.
	CVSS string `json:"cvss"`

	// CVSSScore is the numeric base score corresponding to CVSS.
	CVSSScore float64 `json:"cvss_score"`

	// URL is the specific URL or endpoint where the issue was observed.
	URL string `json:"url,omitempty"`

	// Evidence is the raw signal that triggered the finding: response snippet,
	// header value, payload reflection, etc. Must be reproducible from Repro.
	Evidence string `json:"evidence,omitempty"`

	// Repro is a concrete reproduction step — typically a curl command — so a
	// human reviewer can confirm the finding by hand.
	Repro string `json:"repro,omitempty"`

	// Remediation is the recommended fix, in plain language.
	Remediation string `json:"remediation"`

	// References are URLs to canonical write-ups (OWASP, MDN, vendor docs).
	References []string `json:"references,omitempty"`

	// DetectedAt records when the scanner observed the issue. Useful when the
	// JSON output is consumed by a SIEM or diffed across scans.
	DetectedAt time.Time `json:"detected_at"`
}

// Slug returns a filesystem-safe slug derived from the finding ID and title,
// suitable for use as a markdown filename in 02-findings/.
func (f Finding) Slug() string {
	t := strings.ToLower(f.Title)
	var b strings.Builder
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-', r == '_':
			b.WriteByte('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	return fmt.Sprintf("%s-%s", strings.ToLower(f.ID), slug)
}
