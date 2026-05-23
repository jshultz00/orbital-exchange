# Orbital Exchange

A purposefully vulnerable Juice-Shop-style web app for self-directed OWASP Top 10 practice. Themed as a deep-space station commissary — utilitarian retro-future panels, monospace readouts, amber/cyan CRT accents.

**This is a local-only training target. Do not expose it to the internet.**

## Stack

- **Language:** Go (1.22+ required for `net/http.ServeMux` method+path patterns)
- **Router:** standard library `net/http`
- **Templating:** standard library `html/template` (auto-escaping is the defensive baseline future XSS lessons will break)
- **Database:** SQLite via [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) — pure Go, no CGO
- **Sessions:** [`github.com/alexedwards/scs/v2`](https://github.com/alexedwards/scs) with SQLite-backed store (sessions survive restarts)
- **Password hashing:** `golang.org/x/crypto/bcrypt` (cost 12)

## Run

```sh
go run ./cmd/server
```

App listens on `http://localhost:3000`. On first boot:

1. `data/orbital.sqlite` is created.
2. Schema is applied (idempotent — safe to re-run on every boot).
3. Categories, vulnerabilities, products, and default users are seeded (also idempotent — discovery progress is preserved across reseeds).

Override the port or DB path with env vars:

```sh
ORBITAL_ADDR=":8080" ORBITAL_DB="data/dev.sqlite" go run ./cmd/server
```

## Default credentials

| Account     | Username  | Password         | Role            |
|-------------|-----------|------------------|-----------------|
| Admin       | `command` | `stationcommand` | Station Command |
| Crew member | `ryland`  | `hailmary42`     | Standard crew   |

Seeded on first boot only — change a password in the DB and it persists across reseeds. To add more accounts, edit `defaultUsers` in [internal/seed/seed.go](internal/seed/seed.go).

## Routes

| Method | Path                              | Description |
|--------|-----------------------------------|-------------|
| GET    | `/`                               | Station bulletin / landing |
| GET    | `/catalog`                        | Commissary listing, grouped by category |
| GET    | `/catalog/{slug}`                 | Product detail with Add to Cart form |
| GET    | `/cart`                           | Pending requisition (login required) |
| POST   | `/cart`                           | Add to cart (server validates product/qty) |
| POST   | `/cart/{product_id}/remove`       | Remove a cart line |
| GET    | `/login`, `/register`             | Auth forms |
| POST   | `/login`, `/register`, `/logout`  | Auth actions |
| GET    | `/comms`                          | Comms log — public, anonymous posts allowed |
| POST   | `/comms`                          | Submit a comms entry |
| GET    | `/command`                        | Station Command dashboard (admin only) |
| GET    | `/tracker`                        | Vulnerability tracker — accepts `?difficulty=` and `?status=` filters |
| POST   | `/tracker/reset`                  | Reset all tracker rows to `undiscovered` (admin only) |
| POST   | `/tracker/{id}/discover`          | Flip one tracker row to `discovered` (open by design — called by future planting code) |

## Vulnerability Tracker

`/tracker` is the registry every future spec appends to. The scaffold seeds:

- **10 OWASP 2021 categories** in `categories` table.
- **30 planted-vulnerability slots** (3 per category, mixed easy/medium/hard) in `vulnerabilities` table — all initially `undiscovered`. These are the roadmap; each future increment plants the actual exploit code behind one slot and flips its status.

### Two reset paths

| Path | Touches | When |
|------|---------|------|
| `POST /tracker/reset` (button on `/tracker`, admin only) | Tracker rows only — flips status back to `undiscovered`. Users, cart, comms preserved. | "I want to re-run the drill from scratch." |
| `scripts/wipe-db.sh` | Deletes the SQLite file entirely. Next boot re-seeds everything. | "I want a clean install." |

### Adding a new planted vulnerability

1. Append a row to [`internal/seed/vulnerabilities.json`](internal/seed/vulnerabilities.json) with a fresh slug (e.g. `a03-search-time-based-sqli`).
2. Implement the planted vuln in the relevant handler — deliberately breaking the defensive default that's in place today.
3. From the planting code path, call `POST /tracker/{your-slug}/discover` when the exploit's hidden flag condition is met (or update the row directly via SQL).

The seeder upserts by `id`, preserving any existing progress fields. So you can edit JSON safely on a database that already has discovery state.

## Layout

```
cmd/server/        # entry point
internal/
  config/          # env vars + defaults
  db/              # sqlite open + embedded schema.sql
  seed/            # idempotent seed loader + JSON sources of truth
  session/         # scs session manager + key constants
  views/           # html/template loader (layout + page composition)
  handlers/        # one file per route group: pages, catalog, auth, cart, comms, command, tracker
views/             # html/template files (layout + page bodies)
public/
  css/             # theme.css + tracker.css
  favicon.svg
data/              # runtime SQLite (gitignored)
scripts/           # wipe-db.sh
_specs/            # design docs (gitignored)
```

Module path: `github.com/jshultz00/orbital-exchange`.

## Status

Scaffold complete. **No intentional vulnerabilities planted yet** — the entire codebase currently uses sane defaults (bcrypt, parameterized SQL, html/template auto-escaping, session-token rotation on auth, server-side price/stock validation, admin gating on privileged actions). Future specs deviate from these defaults, one at a time, each referencing the tracker row it plants.
