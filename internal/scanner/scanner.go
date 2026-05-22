package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Scanner runs a configured set of Checks against a Target and aggregates
// their findings. It is intentionally a struct, not a global — that lets
// tests instantiate their own Scanner with fake checks.
type Scanner struct {
	Target *Target
	Checks []Check
	Deps   Deps
}

// New builds a Scanner with the supplied checks. Checks are filtered by
// `enabled`: any ID listed in `enabled` (or its OWASP category prefix, e.g.
// "a05") will be kept. An empty `enabled` slice enables all checks.
func New(target *Target, all []Check, enabled []string, deps Deps) *Scanner {
	if len(enabled) == 0 {
		return &Scanner{Target: target, Checks: all, Deps: deps}
	}
	wanted := make(map[string]struct{}, len(enabled))
	for _, e := range enabled {
		wanted[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
	}
	var kept []Check
	for _, c := range all {
		id := strings.ToLower(c.ID())
		cat := strings.ToLower(c.OWASPCategory())
		if _, ok := wanted[id]; ok {
			kept = append(kept, c)
			continue
		}
		if _, ok := wanted[cat]; ok {
			kept = append(kept, c)
		}
	}
	return &Scanner{Target: target, Checks: kept, Deps: deps}
}

// Result is the aggregate output of a scan, suitable for handing to any
// reporter (terminal/JSON/markdown).
type Result struct {
	Target    string        `json:"target"`
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
	Duration  time.Duration `json:"duration_ns"`
	Findings  []Finding     `json:"findings"`
	Errors    []CheckError  `json:"errors,omitempty"`
}

// CheckError records a non-fatal failure of one check so that operators can
// distinguish "no findings" from "check failed and produced nothing".
type CheckError struct {
	CheckID string `json:"check_id"`
	Error   string `json:"error"`
}

// Run executes every configured check, honouring ctx cancellation between
// checks. Checks run sequentially in Phase A; concurrency is a Phase B+
// optimisation kept off the critical path.
func (s *Scanner) Run(ctx context.Context) *Result {
	r := &Result{
		Target:    s.Target.BaseURL,
		StartedAt: time.Now(),
	}
	for _, c := range s.Checks {
		select {
		case <-ctx.Done():
			r.Errors = append(r.Errors, CheckError{
				CheckID: c.ID(),
				Error:   fmt.Sprintf("skipped: %v", ctx.Err()),
			})
			continue
		default:
		}
		s.Deps.Logger.Infof("running check %s (%s)", c.ID(), c.OWASPCategory())
		findings, err := c.Run(ctx, s.Target, s.Deps)
		if err != nil {
			s.Deps.Logger.Warnf("check %s returned error: %v", c.ID(), err)
			r.Errors = append(r.Errors, CheckError{CheckID: c.ID(), Error: err.Error()})
		}
		r.Findings = append(r.Findings, findings...)
	}
	r.EndedAt = time.Now()
	r.Duration = r.EndedAt.Sub(r.StartedAt)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].CVSSScore != r.Findings[j].CVSSScore {
			return r.Findings[i].CVSSScore > r.Findings[j].CVSSScore
		}
		return r.Findings[i].ID < r.Findings[j].ID
	})
	return r
}
