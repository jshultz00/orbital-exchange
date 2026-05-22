# vulnscope

> A small, deliberately readable Go scanner that detects a defined subset of the OWASP Top 10 (2021) against a local OWASP Juice Shop instance — built end-to-end as a learning project and consultant-style portfolio piece.

`vulnscope` is the executable half of an engagement; the other half is a hand-written assessment report. The whole repository — scanner code, methodology notes, and findings — is structured so it reads like a real consulting deliverable rather than a "look I wrote a scanner" demo.

See [00-scope.md](00-scope.md) for the rules of engagement, [COVERAGE.md](COVERAGE.md) for what the scanner does and does not attempt, and [METHODOLOGY.md](METHODOLOGY.md) for the detection logic of every check.

---

## Quickstart

```bash
# 1. Stand up a disposable Juice Shop on localhost:3000
./juiceshop-start.sh

# 2. Build the scanner
go build -o vulnscope ./cmd/vulnscope

# 3. Run a default scan
./vulnscope --target http://localhost:3000

# 4. Run a subset and get JSON + per-finding markdown
./vulnscope \
    --target http://localhost:3000 \
    --checks a05,a03 \
    --output terminal,json,md \
    --out-dir 02-findings/raw

# 5. Tear down the target
./juiceshop-stop.sh
```

The scanner exits cleanly with no detection modules registered — Phase A ships the engine and reporters first so every later check has a stable home to plug into.

---

## CLI reference

| Flag | Default | Notes |
|---|---|---|
| `--target` | _(required)_ | Base URL of the target, e.g. `http://localhost:3000`. |
| `--checks` | _(all)_ | Comma-separated check IDs or OWASP categories (`a05`, `a03.sqli`). |
| `--output` | `terminal` | Any combination of `terminal`, `json`, `md`. |
| `--out-dir` | `02-findings/raw` | Where JSON/markdown are written. |
| `--rate` | `10` | Max requests per second. `0` = unlimited. |
| `--timeout` | `60s` | Overall scan timeout (ctrl-C also cancels). |
| `--user-agent` | `vulnscope/<ver>` | Override if the lab needs to allow-list the scanner. |
| `--insecure` | `false` | Skip TLS verification (lab only). |
| `--list` | — | Print registered checks and exit. |
| `--verbose` | `false` | Verbose logging. |
| `--version` | — | Print version and exit. |

---

## Repository layout

```
00-scope.md            Engagement scope & rules of engagement
COVERAGE.md            What the scanner detects (and what it does NOT)
METHODOLOGY.md         Per-check detection logic, payloads, signal sources

cmd/vulnscope/         CLI entry point
internal/scanner/      Check interface, Finding/Target types, orchestrator
internal/httpclient/   Single HTTP entry point (UA, timeouts, rate limit)
internal/recon/        Endpoint seed list
internal/report/       terminal / JSON / markdown reporters
internal/checks/       Detection modules — one package per OWASP category
  a05_misconfig/         Phase B (next)
  a03_injection/         Phase C
  a01_access/            Phase D
  a06_components/        Phase E

02-findings/           Per-finding writeups (template + scanner output)
03-report/             Final consultant-style report (assembled last)

juiceshop-start.sh     Disposable target container helper
juiceshop-stop.sh      Tear-down helper
```

---

## Build phases

Each phase ships an executable improvement. The order is **easy → hard** by design — every milestone introduces one new pentest concept, so the project doubles as a learning curriculum.

| Phase | Focus | Pentest skill learned |
|---|---|---|
| **A** ✓ | Skeleton: CLI, orchestrator, HTTP client, reporters, docs | Project layout, structured findings, CVSS basics |
| **B** | **A05 — Security Misconfiguration**: headers, default creds, exposed paths | HTTP security headers; low-effort, high-yield findings |
| **C** | **A03 — Injection**: SQLi (error + boolean), reflected XSS | Payload design, response diffing, false-positive reasoning |
| **D** | **A01 — Broken Access Control / IDOR** | Session/auth handling, multi-user test design |
| **E** | **A06 — Vulnerable & Outdated Components**: fingerprinting + OSV lookup | Passive fingerprinting, public vuln databases |
| **F** | Final docs + manual findings (logic bugs, JWT, 2FA, coupons) | Where automation stops and judgment starts |

### Learning Log

Phase write-ups (one section per detection category) live below as they're built. Each one answers three questions:

1. **What did I implement?**
2. **What did the check find against Juice Shop?**
3. **What did I learn about this vulnerability class that I didn't know before?**

#### Phase A — Skeleton

- **What:** Go module with a `Check` interface, normalized `Finding` shape (CVSS vector + score + severity band), a shared HTTP client with explicit timeouts and a hand-rolled rate limiter, and three pluggable reporters.
- **What it found:** nothing yet — no checks are registered.
- **What I learned:**
  - Every reportable issue must travel through one normalized struct or the report-writing phase becomes impossible. The `Finding` shape is the unit of work, not the check.
  - "Follow redirects" is the wrong default for a scanner — header checks need the *first* response, not what the redirect resolves to.
  - Recording the full CVSS vector (`CVSS:3.1/AV:N/...`), not just the numeric score, is what separates consultant-grade output from amateur output.

_(Phases B–F will append their own subsection here as they land.)_

---

## Verification per phase

```bash
./juiceshop-start.sh
go test ./...
go build -o vulnscope ./cmd/vulnscope
./vulnscope --target http://localhost:3000 --output terminal,json,md --out-dir 02-findings/raw
# Reproduce each finding by hand with curl/Burp; record in 02-findings/<slug>.md
./juiceshop-stop.sh
```

Acceptance criterion for the whole project: a recruiter can `git clone`, `./juiceshop-start.sh`, `go run ./cmd/vulnscope --target http://localhost:3000`, and have real findings printed within ~30 seconds.

---

## Legal & scope

All testing is performed against software the author owns and operates locally. Juice Shop is published by OWASP as an intentionally vulnerable training target. No third-party systems are touched at any point. The full statement is in [00-scope.md](00-scope.md) §2.
