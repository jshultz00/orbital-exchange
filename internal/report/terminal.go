// Package report emits scan results in three formats:
//
//   - Terminal: ANSI-coloured, designed for live operator feedback.
//   - JSON:     stable schema for downstream tooling (SIEM, CI, jq).
//   - Markdown: one file per finding, ready to be hand-edited into the
//     final consultant-style report.
//
// All three reporters consume *scanner.Result, so adding a new format means
// implementing one function, not touching any check.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/jshultz/vulnscope/internal/scanner"
)

// ANSI colour codes — small constant set so we don't pull in a colour lib.
const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cDim    = "\x1b[2m"
	cRed    = "\x1b[31m"
	cYellow = "\x1b[33m"
	cBlue   = "\x1b[34m"
	cGreen  = "\x1b[32m"
	cGray   = "\x1b[90m"
)

func sevColor(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical:
		return cRed + cBold
	case scanner.SeverityHigh:
		return cRed
	case scanner.SeverityMedium:
		return cYellow
	case scanner.SeverityLow:
		return cBlue
	default:
		return cGray
	}
}

// Terminal writes a human-readable summary of r to w. If color is false,
// no ANSI escapes are emitted (useful when stdout is not a TTY).
func Terminal(w io.Writer, r *scanner.Result, color bool) {
	paint := func(c, s string) string {
		if !color {
			return s
		}
		return c + s + cReset
	}
	fmt.Fprintln(w, paint(cBold, "vulnscope scan complete"))
	fmt.Fprintf(w, "  target:    %s\n", r.Target)
	fmt.Fprintf(w, "  duration:  %s\n", r.Duration.Round(1e6))
	fmt.Fprintf(w, "  findings:  %d\n", len(r.Findings))
	if len(r.Errors) > 0 {
		fmt.Fprintf(w, "  %s %d\n", paint(cYellow, "check errors:"), len(r.Errors))
	}
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, paint(cGreen, "no findings"))
		return
	}
	counts := map[scanner.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "  %s C:%d H:%d M:%d L:%d I:%d\n", paint(cDim, "by severity:"),
		counts[scanner.SeverityCritical], counts[scanner.SeverityHigh],
		counts[scanner.SeverityMedium], counts[scanner.SeverityLow],
		counts[scanner.SeverityInfo])
	fmt.Fprintln(w)
	for _, f := range r.Findings {
		fmt.Fprintf(w, "%s  %s  %s\n",
			paint(sevColor(f.Severity), fmt.Sprintf("[%s]", strings.ToUpper(string(f.Severity)))),
			paint(cBold, f.ID),
			f.Title,
		)
		if f.URL != "" {
			fmt.Fprintf(w, "    %s %s\n", paint(cDim, "URL:"), f.URL)
		}
		if f.CVSS != "" {
			fmt.Fprintf(w, "    %s %s (%.1f)\n", paint(cDim, "CVSS:"), f.CVSS, f.CVSSScore)
		}
		if f.Evidence != "" {
			ev := f.Evidence
			if len(ev) > 200 {
				ev = ev[:200] + "..."
			}
			fmt.Fprintf(w, "    %s %s\n", paint(cDim, "evidence:"), ev)
		}
		fmt.Fprintln(w)
	}
}
