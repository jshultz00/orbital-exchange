package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jshultz/vulnscope/internal/scanner"
)

// Markdown writes one .md file per finding under outDir. It also writes a
// summary index at outDir/INDEX.md listing every finding by severity.
//
// LEARNING NOTE: each emitted file follows the same shape as the manual
// finding template in 02-findings/_template.md. That alignment is on purpose:
// a hand-written finding and a scanner-emitted finding are indistinguishable
// to the final report, so the consultant phase can mix them freely.
func Markdown(outDir string, r *scanner.Result) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, f := range r.Findings {
		path := filepath.Join(outDir, f.Slug()+".md")
		if err := os.WriteFile(path, []byte(renderFinding(f)), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	idx := filepath.Join(outDir, "INDEX.md")
	if err := os.WriteFile(idx, []byte(renderIndex(r)), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", idx, err)
	}
	return nil
}

func renderFinding(f scanner.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — %s\n\n", f.ID, f.Title)
	fmt.Fprintf(&b, "> **Severity:** %s &nbsp;·&nbsp; **CVSS:** %s (%.1f) &nbsp;·&nbsp; **Category:** %s\n\n",
		f.Severity, f.CVSS, f.CVSSScore, f.OWASPCategory)
	fmt.Fprintf(&b, "## Description\n\n%s\n\n", f.Description)
	if f.URL != "" {
		fmt.Fprintf(&b, "## Affected\n\n- URL: `%s`\n- Check: `%s`\n- Detected: %s\n\n",
			f.URL, f.CheckID, f.DetectedAt.Format("2006-01-02 15:04:05 MST"))
	}
	if f.Evidence != "" {
		fmt.Fprintf(&b, "## Evidence\n\n```\n%s\n```\n\n", f.Evidence)
	}
	if f.Repro != "" {
		fmt.Fprintf(&b, "## Reproduction\n\n```bash\n%s\n```\n\n", f.Repro)
	}
	fmt.Fprintf(&b, "## Remediation\n\n%s\n\n", f.Remediation)
	if len(f.References) > 0 {
		fmt.Fprintln(&b, "## References")
		for _, ref := range f.References {
			fmt.Fprintf(&b, "- %s\n", ref)
		}
	}
	return b.String()
}

func renderIndex(r *scanner.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Scan Index — %s\n\n", r.Target)
	fmt.Fprintf(&b, "- Started: %s\n", r.StartedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "- Duration: %s\n", r.Duration.Round(1e6))
	fmt.Fprintf(&b, "- Findings: %d\n\n", len(r.Findings))
	fmt.Fprintln(&b, "| ID | Severity | Category | Title |")
	fmt.Fprintln(&b, "|---|---|---|---|")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| [%s](%s.md) | %s | %s | %s |\n",
			f.ID, f.Slug(), f.Severity, f.OWASPCategory, f.Title)
	}
	return b.String()
}
