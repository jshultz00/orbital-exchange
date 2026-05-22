# COVERAGE.md — what `vulnscope` does and does NOT detect

> A scanner that won't tell you where it stops is a scanner you can't trust. This document is the explicit coverage contract for `vulnscope`. Every entry says **WHAT** is checked, **WHY** that approach was chosen, and **WHERE the detection breaks down** (the false positives and false negatives a human reviewer must catch).

This file is read alongside [00-scope.md](00-scope.md) (the engagement contract) and [METHODOLOGY.md](METHODOLOGY.md) (the payload-level detail).

---

## Coverage at a glance

| OWASP 2021 ID | Category | Status | Phase | Confidence |
|---|---|---|---|---|
| A01 | Broken Access Control | Planned | D | Medium–High (with valid sessions) |
| A02 | Cryptographic Failures | **Out — manual** | — | — |
| A03 | Injection (SQLi, reflected XSS) | Planned | C | High for SQLi; Medium for XSS |
| A04 | Insecure Design | **Out — manual** | — | — |
| A05 | Security Misconfiguration | Planned | B | High (headers); Medium (exposed paths) |
| A06 | Vulnerable & Outdated Components | Planned | E | Medium (depends on fingerprint quality) |
| A07 | Identification & Auth Failures | **Out — partial manual** | — | — |
| A08 | Software & Data Integrity Failures | **Out — manual** | — | — |
| A09 | Security Logging & Monitoring Failures | **Out — not externally observable** | — | — |
| A10 | Server-Side Request Forgery | **Out — manual this iteration** | — | — |

Phase column references the build phases in [README.md](README.md#build-phases).

---

## A01 — Broken Access Control (IDOR)

### What the scanner does
Registers two synthetic test users (`userA`, `userB`) via Juice Shop's signup endpoint, logs both in, then issues requests as `userB` for resources known to belong to `userA`:

- `GET /api/Users/<A_id>`
- `GET /rest/basket/<A_id>`
- `GET /api/Recycles/<A_id>`

A finding is raised when `userB` receives `userA`'s data with a 2xx status.

### Why this approach
IDOR is the canonical bug class that *cannot* be detected without two valid perspectives. The "diff two perspectives" pattern is exactly what a human pentester does in Burp; the scanner just automates it.

### Known limits (FP / FN profile)
- **FN:** The scanner only probes a curated list of endpoints. IDOR on a custom endpoint we don't know about will be missed — manual API discovery is still required.
- **FN:** Numeric IDs only. If Juice Shop uses opaque or UUID identifiers anywhere, the scanner has no way to guess `userA`'s ID.
- **FP, low:** A 2xx with empty/sanitised data from `userB` could look like an IDOR but actually be the intended "list returns your own resources" behaviour. The scanner compares response bodies, not just status codes, to reduce this.

---

## A03 — Injection

### What the scanner does
Two independent detectors:

**SQL Injection** (`a03.sqli`)
- Targets: `/rest/user/login` (`email` field) and `/rest/products/search` (`q` query string).
- Error-based: send `'`, `"`, `\`. Flag if the response body contains known SQL error fragments (`SQLITE_ERROR`, `Unclosed quotation`, `syntax error`, etc.).
- Boolean-based: send a true-pair (`' OR 1=1--`) and a false-pair (`' AND 1=2--`). Flag if status / length / body diff materially.

**Reflected XSS** (`a03.xss`)
- Inject a unique canary (e.g. `<vs7f3a>"'>`) into known reflective parameters (`q`, profile fields).
- Flag if the canary appears unencoded in the response body, with HTML context.

### Why this approach
Error-based SQLi is the highest-signal SQLi detection that exists; if the app surfaces a SQL error fragment, false positives are essentially zero. Boolean-based catches the case where errors are hidden but behaviour still diverges. For XSS, "canary reflected without encoding" is the same signal Burp Active Scan uses.

### Known limits (FP / FN profile)
- **FN:** Blind, time-based, and second-order SQLi are not attempted (Phase scope; deferred to manual).
- **FN:** Stored XSS is not attempted. Stored XSS requires multi-step session orchestration that isn't worth automating until A01 lands.
- **FP, low:** A reflective error-page template could trigger error-based SQLi false positives. Findings include the matched error fragment so a reviewer can quickly dismiss.
- **FP, low:** XSS canary reflection inside `<textarea>` / `<title>` is technically a different escape context — the scanner reports it; the human decides exploitability.

---

## A05 — Security Misconfiguration

### What the scanner does
Three detectors:

**Headers** (`a05.headers`) — for the root document, check presence and (where simple) quality of:
- `Content-Security-Policy`
- `Strict-Transport-Security` _(downgraded to Info on `http://localhost` — see below)_
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

**Default credentials** (`a05.default_creds`) — try the documented Juice Shop admin email against a tiny weak-password wordlist.

**Exposed paths** (`a05.exposed_paths`) — probe `/ftp`, `/ftp/`, `/metrics`, `/administration`, `/.git/HEAD`, `/api-docs`, `/swagger`. Flag a 200 + content-type heuristic.

### Why this approach
Header checks are the cheapest, highest-signal items in any web pentest — a missing `X-Content-Type-Options` is unambiguous. Exposed admin/metrics paths are similarly black-and-white. Default creds is purely a "did anyone change the password" sanity check.

### Known limits (FP / FN profile)
- **Context, not FP:** HSTS over `http://localhost` is not actually missing — it's *meaningless* there. The check downgrades severity to Informational so the finding still appears (for completeness) without false alarm.
- **FN:** "Weak" CSP detection is intentionally not attempted — judging whether a CSP is actually effective requires understanding the app's needs. The check reports presence only.
- **FP, low:** Exposed paths heuristic accepts a 200 + non-default content type. A custom 404 page that returns 200 will trip this; reviewer must confirm.

---

## A06 — Vulnerable & Outdated Components

### What the scanner does
Passively fingerprint:
- `Server` / `X-Powered-By` headers.
- `/package.json` if exposed (Juice Shop notoriously is).
- Inline `<script src="…">` references with versioned filenames.

Cross-reference each `(package, version)` against the public **OSV.dev REST API** (free, no key). Output one Finding per package with ≥1 matching advisory; severity is the max CVSS of matched advisories.

### Why this approach
Passive fingerprinting + a public vuln DB is the highest signal-to-noise component detection that exists outside commercial scanners. OSV.dev is the right choice (free, JSON, no API key, maintained by Google) — picking a paid CVE provider would be a poor portfolio choice.

### Known limits (FP / FN profile)
- **FN:** No version → no lookup. If the page doesn't leak the version, the scanner cannot detect a vuln in it.
- **FP, medium:** OSV advisories sometimes apply only to specific configurations (Node version, OS). The scanner reports the advisory; the reviewer judges applicability.

---

## Categories the scanner intentionally does NOT detect

These appear in the manual phase of the engagement (see [00-scope.md](00-scope.md) §6).

| ID | Why automation is unreliable |
|---|---|
| A02 Cryptographic Failures | Requires judgment on data sensitivity and threat model. Pattern-matching for "weak hash" produces useless findings without context. |
| A04 Insecure Design | A design-level flaw class. No payload exists for "the workflow itself is broken". |
| A07 Identification & Auth Failures | JWT `none` algorithm, password-reset flow bugs, 2FA bypass — these need session orchestration the scanner doesn't have yet. Partially automatable in a future phase. |
| A08 Software & Data Integrity Failures | Needs supply-chain and CI/CD context the scanner can't see. |
| A09 Security Logging & Monitoring Failures | Not observable from an external scan, by definition. |
| A10 Server-Side Request Forgery | In scope for the manual testing phase. Reliable SSRF detection generally requires a callback infrastructure (Burp Collaborator-style) — out of scope here. |
| Business logic flaws | The Juice Shop "challenge" puzzles (coupon brute-force, score-board access, basket manipulation) are explicitly handled in manual testing. Logic flaws are the most valuable part of any real engagement — but they are also the part automation is worst at. |

---

## Reading this file alongside findings

When you read a finding in `02-findings/`, you should be able to map it back to one row in this document. If a finding doesn't appear in either an automated check row or the manual-testing list, the scope drifted. Update [00-scope.md](00-scope.md) before adding new categories here.
