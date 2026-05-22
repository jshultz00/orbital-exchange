# METHODOLOGY.md — how each check actually works

> [COVERAGE.md](COVERAGE.md) answers _what_. This document answers _how_. Every check is documented here with its payloads, its signal sources, and the OWASP WSTG / API Security Top 10 references it implements. The goal: a reader who has never touched the code can predict exactly what HTTP traffic the scanner will produce against a target.

The check IDs here match the ones the scanner prints under `--list`, and the WSTG / OWASP API IDs are deliberately preserved so findings speak the language a hiring pentest lead recognises.

---

## Engagement phases (PTES)

| # | Phase | Where it lives |
|---|---|---|
| 1 | Recon & enumeration | `internal/recon/`, plus `--list` output |
| 2 | Automated scanning | `internal/checks/...` |
| 3 | Manual verification | `02-findings/` — every automated finding is reproduced by hand |
| 4 | Manual discovery | `02-findings/` — logic bugs the scanner cannot find by design |
| 5 | Reporting | `03-report/` — final consultant-style writeup |

A finding does not enter the final report until step 3 reproduces it independently. The scanner is the *first* signal, not the last word.

---

## Severity & scoring

All findings carry a CVSS v3.1 base vector — not just the numeric score. The vector is the audit trail: a reviewer can disagree with our severity but they can _trace_ the disagreement. Score bands match the FIRST.org standard ([00-scope.md](00-scope.md) §9).

The `Finding.CVSS` field is the full string, e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`. The numeric `Finding.CVSSScore` is computed from that vector and must be consistent with it.

---

## A05 — Security Misconfiguration

### `a05.headers` — Missing security headers (WSTG-CONF-07)

**HTTP traffic:** one `GET /` to the target root.

**Detection logic:** for each header in the table below, compare the response against the expected presence. Each missing header is one Finding.

| Header | Expected presence | If missing | CVSS context |
|---|---|---|---|
| `Content-Security-Policy` | required | Finding — Low / Medium | The single biggest XSS-defense-in-depth header. |
| `Strict-Transport-Security` | required on HTTPS | Finding — _Info on `http://`_ | HSTS over `http` is non-applicable; we downgrade severity rather than skip. |
| `X-Frame-Options` _or_ `frame-ancestors` in CSP | one of the two | Finding — Low | Clickjacking defense. CSP `frame-ancestors` supersedes XFO. |
| `X-Content-Type-Options: nosniff` | required | Finding — Low | MIME-sniffing defence. |
| `Referrer-Policy` | required | Finding — Info | Information leak defence. |
| `Permissions-Policy` | recommended | Finding — Info | Feature-policy lockdown. |

**Reference:** OWASP Secure Headers Project, MDN security headers documentation.

### `a05.default_creds` — Default credentials (WSTG-ATHN-02)

**HTTP traffic:** ≤6 `POST /rest/user/login` attempts, with a small wordlist of well-known weak passwords against the documented Juice Shop admin email.

**Detection logic:** Juice Shop returns an `authentication` JSON object with a token on success and a 4xx on failure. Receiving a token is the signal.

**Reference:** WSTG-ATHN-02.

### `a05.exposed_paths` — Unintentionally exposed paths (WSTG-CONF-04, CONF-05)

**HTTP traffic:** one `GET` per path in the list:
`/ftp`, `/ftp/`, `/metrics`, `/administration`, `/.git/HEAD`, `/api-docs`, `/swagger`.

**Detection logic:**
- Path returns 200 → candidate finding.
- Content-Type is _not_ the application's default HTML 200 page (heuristic: distinct length + content sniff) → confirmed finding.

**Reference:** WSTG-CONF-04 (admin interfaces), WSTG-CONF-05 (file extensions/handlers).

---

## A03 — Injection

### `a03.sqli` — SQL Injection (WSTG-INPV-05)

**HTTP traffic:**
1. **Baseline:** unmodified request → record status, content-length, body hash.
2. **Error-based:** repeat with each of `'`, `"`, `\`. Match response body against an error-signature table.
3. **Boolean-based:** send a true-pair payload (`' OR '1'='1`) and a false-pair (`' OR '1'='2`); compare the two responses.

**Targets in Phase C:**
- `POST /rest/user/login` — `email` and `password` fields.
- `GET /rest/products/search?q=...` — `q` parameter.

**Error-fragment signature table** (illustrative; full list in `internal/checks/a03_injection/sqli.go`):

| Engine | Fragment to match (case-insensitive) |
|---|---|
| SQLite | `SQLITE_ERROR`, `unrecognized token`, `unclosed quotation` |
| MySQL | `you have an error in your sql syntax`, `mysql_fetch` |
| Postgres | `pg_query`, `unterminated quoted string` |
| MSSQL | `microsoft odbc`, `incorrect syntax near` |

**Signals & confidence:**
| Signal | Confidence |
|---|---|
| Known error fragment in response | High — virtually no false positives. |
| Status code differs between `'` and baseline | Medium. |
| Boolean-pair body lengths diverge by >5% | Medium. |
| Boolean-pair status differs | High. |

**Reference:** WSTG-INPV-05.

### `a03.xss` — Reflected Cross-Site Scripting (WSTG-INPV-01)

**HTTP traffic:** one request per (endpoint, parameter) pair in the reflective-param list. The injected value is a per-scan canary of the form `<vsXXXX>"'>` where `XXXX` is a random hex string — unique per scan, so reflections from previous scans never produce false positives.

**Detection logic:**
- Reflected canary appears in response body **exactly as sent** → Finding.
- Reflected canary appears but the `<`, `>`, `"`, `'` characters are HTML-encoded → not a finding; encoding works.
- Reflected canary appears inside a `<script>` block or `on*` attribute → upgrade severity.

**Reference:** WSTG-INPV-01 (Reflected XSS).

---

## A01 — Broken Access Control (IDOR)

### `a01.idor` — Insecure Direct Object Reference (API1:2023, WSTG-ATHZ-04)

**Setup (one-time per scan):**
1. `POST /api/Users` — register `userA@vulnscope.test`, capture returned ID.
2. `POST /api/Users` — register `userB@vulnscope.test`, capture returned ID.
3. `POST /rest/user/login` for each user, capture JWT.

**Probe loop:** for every protected endpoint that takes a numeric resource ID:
- Issue `request_as(userA, A_id)` and `request_as(userB, A_id)`.
- Compare responses.

**Decision matrix:**

| `userA` status | `userB` status | Bodies equal? | Verdict |
|---|---|---|---|
| 2xx | 2xx | yes | **Finding — IDOR confirmed** (B reads A's data) |
| 2xx | 2xx | no | Inspect — might be filtered view |
| 2xx | 401/403 | — | Correct; no finding |
| 2xx | 404 | — | Correct enumeration defence; no finding |

**Reference:** OWASP API Security Top 10 — API1:2023, WSTG-ATHZ-04.

**Why this is the resume-grade part of the scanner.** Most CTF-style scanners can't do A01 at all — they don't bother with auth. Wiring up two real sessions and diffing is the same pattern a human consultant runs in Burp's Repeater, just automated.

---

## A06 — Vulnerable & Outdated Components

### `a06.fingerprint` + `a06.cve_lookup` — Stack fingerprinting + OSV lookup (WSTG-CONF-02)

**Fingerprint sources, in order of confidence:**
1. `GET /package.json` — Juice Shop exposes its own manifest. Highest signal.
2. `Server` / `X-Powered-By` response headers on `/`.
3. `<script src="…version…">` references in the root HTML.

**Lookup:**
- For each `(package, version)` pair, POST to `https://api.osv.dev/v1/query` with `{ package: {name, ecosystem}, version }`.
- Each returned advisory → finding. Severity = max CVSS across the package's advisories.

**Why OSV.dev:** free, JSON, no API key, actively maintained by Google. Matches the "open-source preferred" preference in CLAUDE.md and gives the project a free, real CVE database without any commercial-tier signup.

**Reference:** WSTG-CONF-02 (Application platform configuration).

---

## Manual phase — what the scanner does not look for

The scanner produces a draft list of findings. The manual phase fills three gaps:

1. **Verify every automated finding.** Reproduce with curl/Burp, record the repro in `02-findings/<id>-<slug>.md`. Anything that can't be reproduced is dropped.
2. **Hunt logic bugs.** Juice Shop's puzzles (coupon brute-force, score-board access, JWT `none` algorithm, 2FA bypass on admin) — these are the OWASP A04 / A07 examples and they require human judgment.
3. **Triage by exploit impact.** Re-rate severity based on observed impact, not just the CVSS base score.

The output of the manual phase replaces, not supplements, the raw scanner output.
