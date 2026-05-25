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

## Installation

Prerequisites:

- Go 1.22 or newer
- Git

Clone the public repository:

```sh
git clone https://github.com/jshultz00/orbital-exchange.git
cd orbital-exchange
go mod download
```

If you downloaded the ZIP from GitHub instead, extract it, open a terminal in the extracted `orbital-exchange` directory, and run:

```sh
go mod download
```

No external database service is required. The app creates a local SQLite file under `data/` on first boot.

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

To build a local binary instead:

```sh
mkdir -p bin
go build -o bin/orbital-exchange ./cmd/server
./bin/orbital-exchange
```

## Usage

1. Start the server and open `http://localhost:3000`.
2. Sign in with the standard crew account below, or register a fresh crew account from `/register`.
3. Explore the commissary, cart, manifests, crew roster, comms log, and tracker from the top navigation.
4. Use `/tracker` to pick a challenge. Hints are hidden by default; choose **Reveal hint** only when you want help.
5. When a hidden success condition is met, the matching tracker row flips to `discovered`.

For repeat practice, use the tracker reset button to clear discovery status while preserving users, carts, and comms. For a clean install, stop the server and run:

```sh
./scripts/wipe-db.sh
```

## Default credentials

| Account     | Username  | Password                  | Role            |
|-------------|-----------|---------------------------|-----------------|
| Admin       | `command` | Intentionally undisclosed | Station Command |
| Crew member | `ryland`  | `hailmary42`              | Standard crew   |

The Station Command password is intentionally undisclosed in docs; it is part of the training target. Seeded accounts are created on first boot only — change a password in the DB and it persists across reseeds. To add more accounts, edit `defaultUsers` in [internal/seed/seed.go](internal/seed/seed.go).

## Spoiler policy

This README is for running and extending the app, not solving it. It lists ordinary navigation and maintenance routes, but it does not disclose hidden paths, exploit mechanics, tokens, admin secrets, or exact trigger conditions. Use `/tracker` hints when you want a nudge during practice.

## Routes

These are the normal app and maintenance surfaces. Some challenge-only behavior is intentionally omitted or described broadly.

| Method | Path                                   | Description |
|--------|----------------------------------------|-------------|
| GET    | `/`                                    | Station bulletin / landing |
| GET    | `/catalog`                             | Commissary listing, grouped by category |
| GET    | `/catalog/{slug}`                      | Product detail with Add to Cart form |
| GET    | `/cart`                                | Pending requisition (login required) |
| POST   | `/cart`                                | Add to cart (server validates product/qty) |
| POST   | `/cart/{product_id}/remove`            | Remove a cart line |
| POST   | `/cart/voucher`                        | Apply a ration voucher code |
| POST   | `/cart/checkout`                       | Submit the requisition and create a manifest |
| GET    | `/manifest`                            | Your own requisition manifests (login required) |
| GET    | `/manifest/{id}`                       | Manifest detail (login required) |
| GET    | `/manifest/export`                     | Manifest export API referenced in-app |
| GET    | `/crew`                                | Crew roster (login required) |
| GET    | `/crew/{id}`                           | Crew roster detail (login required) |
| GET    | `/avatar`                              | Avatar upload form (login required) |
| POST   | `/avatar`                              | Upload a crew avatar image |
| GET    | `/login`, `/register`                  | Auth forms |
| POST   | `/login`, `/register`, `/logout`       | Auth actions |
| GET    | `/reset`                               | Password reset request form |
| POST   | `/reset`                               | Submit reset request |
| GET    | `/reset/confirm`                       | Password reset confirmation form (token required) |
| POST   | `/reset/confirm`                       | Submit new password |
| GET    | `/comms`                               | Comms log — public, anonymous posts allowed |
| POST   | `/comms`                               | Submit a comms entry |
| POST   | `/comms/{id}/delete`                   | Delete a comms entry (admin only) |
| GET    | `/command`                             | Station Command dashboard (admin only) |
| POST   | `/command/crew/{id}/toggle-admin`      | Grant or revoke crew admin status (admin only) |
| GET    | `/tracker`                             | Vulnerability tracker — accepts `?difficulty=` and `?status=` filters |
| POST   | `/tracker/reset`                       | Reset all tracker rows to `undiscovered` (admin only) |
| POST   | `/tracker/{id}/discover`               | Internal training hook for planted challenge code |

## Vulnerability Tracker

`/tracker` is the registry every future spec appends to. The tracker shows only planted rows and keeps each row's hint hidden until the user chooses **Reveal hint**.

The app ships with **36 vulnerabilities fully planted**, mixed easy/medium/hard:

- **10 OWASP 2025 categories** in `categories` table.
- **36 vulnerability slots** in `vulnerabilities` table — all marked `is_planted: true` with live exploit surfaces wired into handlers.

A full write-up for each challenge (what it is, how it works here, real-world context, detection, and fix) is in [docs/vulnerabilities.md](docs/vulnerabilities.md).

### Two reset paths

| Path | Touches | When |
|------|---------|------|
| `POST /tracker/reset` (button on `/tracker`, admin only) | Tracker rows only — flips status back to `undiscovered`. Users, cart, comms preserved. | "I want to re-run the drill from scratch." |
| `scripts/wipe-db.sh` | Deletes the SQLite file entirely. Next boot re-seeds everything. | "I want a clean install." |

### Adding a new planted vulnerability

1. Append a row to [`internal/seed/vulnerabilities.json`](internal/seed/vulnerabilities.json) with a fresh slug (e.g. `a05-search-time-based-sqli`) and a `hint`.
2. Implement the planted vuln in the relevant handler — deliberately breaking the defensive default that's in place today.
3. From the planting code path, call `POST /tracker/{your-slug}/discover` when the hidden success condition is met (or update the row directly via SQL).

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
  handlers/        # one file per route group or challenge surface
docs/              # full vulnerability write-ups (vulnerabilities.md)
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

All 36 vulnerabilities are planted and live. Each handler intentionally deviates from the defensive baseline and references the tracker row it satisfies. Every planted challenge flips its tracker row to `discovered` when its hidden success condition fires.

The README avoids listing planted surfaces and solutions; use the app and tracker hints for practice, or consult [docs/vulnerabilities.md](docs/vulnerabilities.md) for the full reference.
