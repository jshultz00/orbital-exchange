-- Orbital Exchange schema. Idempotent: every statement is CREATE ... IF NOT EXISTS,
-- so running it on an existing database is a no-op.

-- Crew members. is_admin flips a user into Station Command access.
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Commissary inventory. price is in "credits" (in-fiction currency).
-- slug is a URL-friendly identifier used in /catalog/{slug}.
CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    slug        TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    category    TEXT    NOT NULL, -- e.g. ration / oxygen / salvage
    description TEXT    NOT NULL,
    price       INTEGER NOT NULL,
    stock       INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One row per (user, product) currently in the user's cart.
-- Cart requires login; guests are redirected to /login.
CREATE TABLE IF NOT EXISTS cart_items (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    qty        INTEGER NOT NULL CHECK (qty > 0),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, product_id)
);

-- Comms log / feedback entries. user_id nullable for unauthenticated submissions
-- (the form is open by design — future SSRF/XSS planting may live here).
CREATE TABLE IF NOT EXISTS comms_entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    author     TEXT    NOT NULL, -- display name (logged-in or "Anonymous Crew")
    body       TEXT    NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerability tracker schema.
--
-- Two tables: categories (the 10 OWASP 2021 buckets) and vulnerabilities
-- (concrete planted vulns, many per category). The seeder loads both from
-- internal/seed/{categories,vulnerabilities}.json and upserts by id,
-- preserving discovery progress on re-seed.

CREATE TABLE IF NOT EXISTS categories (
    id         TEXT    PRIMARY KEY, -- short slug: a01, a02, ... a10
    name       TEXT    NOT NULL,    -- "A01:2021 - Broken Access Control"
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id             TEXT    PRIMARY KEY,                  -- slug, e.g. a01-airlock-manifest-override
    category_id    TEXT    NOT NULL REFERENCES categories(id),
    title          TEXT    NOT NULL,                     -- in-fiction title
    description    TEXT    NOT NULL,                     -- crew-facing flavor + technical hint
    difficulty     TEXT    NOT NULL DEFAULT 'medium'
        CHECK (difficulty IN ('easy', 'medium', 'hard')),
    status         TEXT    NOT NULL DEFAULT 'undiscovered'
        CHECK (status IN ('undiscovered', 'discovered', 'exploited')),
    discovered_at  TIMESTAMP NULL,
    notes          TEXT    NULL,
    sort_order     INTEGER NOT NULL DEFAULT 0            -- sort within category
);
CREATE INDEX IF NOT EXISTS vulnerabilities_category_idx ON vulnerabilities(category_id, sort_order);
CREATE INDEX IF NOT EXISTS vulnerabilities_status_idx   ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS vulnerabilities_difficulty_idx ON vulnerabilities(difficulty);

-- Sessions table for github.com/alexedwards/scs/v2 + sqlite3store. The store
-- does NOT auto-create this — schema is required up front. See:
-- https://github.com/alexedwards/scs/blob/master/sqlite3store/README.md
CREATE TABLE IF NOT EXISTS sessions (
    token  TEXT    PRIMARY KEY,
    data   BLOB    NOT NULL,
    expiry REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expiry);
