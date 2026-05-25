# Orbital Exchange — Vulnerability Reference

Each entry covers the vulnerability class, the CWE, how the specific instance
works in this app, why the pattern matters in real systems, where it commonly
appears in the wild, how to spot it during a test, and the fix for this exact
implementation.

---

## A01 — Broken Access Control

### a01-airlock-manifest-override · Override the airlock manifest

**CWE-639 — Authorization Bypass Through User-Controlled Key**

**What it is.** An Insecure Direct Object Reference (IDOR): a user can
substitute any record identifier in a URL to reach data that belongs to another
user, because the server trusts the client-supplied ID without confirming
ownership.

**How it works here.** `GET /manifest/{id}` in
[manifest.go](../internal/handlers/manifest.go) fetches the manifest row by
primary key only — no `WHERE user_id = session_user_id` guard. Any
authenticated crew member can iterate integer IDs in the URL to pull another
crew member's order history.

**Why this matters.** IDOR is one of the most common web vulnerabilities; it
exposes private data across account boundaries and is trivial to exploit with
no special tooling. At scale the entire dataset can be bulk-enumerated.

**Where it commonly appears.** REST endpoints that address resources by a
sequential database primary key (e.g., `/orders/1042`, `/invoices/7`), profile
pages, file download links, and any API that echoes a record ID back to the
client.

**How to find it.** Log in as two different users. Capture the numeric ID that
appears in your own resource URL. Replace it with the other user's ID
(discovered via any other means — roster page, adjacent integer, etc.) and
observe whether the server returns their data without an authorization error.

**Fix for this implementation.** Add a `user_id` equality check to the query in
`Manifest.Detail`:

```go
// Replace:
WHERE m.id = ?

// With:
WHERE m.id = ? AND m.user_id = ?
// and pass (id, user.ID) as arguments.
```

Alternatively, fetch the row and compare `detail.OwnerID != user.ID` before
rendering; return 403 if they differ. (The comparison is already there for
tracker-flip detection — just change the branch from flip→continue to
flip→http.Error→return.)

---

### a01-crew-roster-idor · Read another crew member's roster entry

**CWE-639 — Authorization Bypass Through User-Controlled Key**

**What it is.** Same IDOR class as the manifest override above, but here the
exposed object is a crew member's profile row, which includes their
`station_key` — the API credential used to authenticate against
`/manifest/export`.

**How it works here.** `GET /crew/{id}` in
[crew.go](../internal/handlers/crew.go) fetches any user row by ID with no
ownership check. The detail template renders the `station_key` field, so
reading another crew member's profile harvests their API token.

**Why this matters.** Combining account enumeration (guessing IDs) with a
leaked API key is a two-step chain that grants access to the manifest-export
endpoint under another identity — a privilege escalation from IDOR alone.

**Where it commonly appears.** Profile pages, user-settings endpoints, and any
resource that stores credentials or sensitive personal data addressed by a
sequential integer.

**How to find it.** Same pattern: authenticated session, two accounts, swap the
ID in the URL. Look specifically for sensitive fields (tokens, emails, SSNs)
in the rendered output.

**Fix for this implementation.** In `Crew.Detail`, after fetching the row:

```go
if detail.ID != user.ID && !user.IsAdmin {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}
```

Move the existing IDOR-detect branch above the render call and change it to a
hard deny instead of a silent flip.

---

### a01-station-key-manifest-dump · Exfiltrate the full manifest ledger with a stolen station key

**CWE-285 — Improper Authorization**

**What it is.** A privilege escalation via a stolen credential: once an admin's
`station_key` is obtained (e.g., via the crew IDOR above), it is used to call a
privileged export endpoint that returns data for all users.

**How it works here.** `GET /manifest/export?key=<station_key>` in
[manifest.go](../internal/handlers/manifest.go) resolves the key to a user row
and — when `is_admin = 1` — executes an unrestricted `SELECT` returning every
manifest in the database. No additional check confirms the caller's *intent* or
that the key was legitimately obtained.

**Why this matters.** Credential theft followed by API misuse is the canonical
data exfiltration path. Scoping "admin key → full dataset" behind a single
query parameter with no second factor, IP allowlist, or scope confirmation
makes exfiltration silent and low-effort.

**Where it commonly appears.** Internal API endpoints designed for reporting or
ETL pipelines that use long-lived shared secrets instead of scoped tokens.

**How to find it.** Obtain an admin station key (via the IDOR chain). Submit it
to the export endpoint. Observe whether the response contains rows that don't
belong to the key owner.

**Fix for this implementation.** The export endpoint should either (a) scope
admin exports to an explicit `scope=export` parameter that is separately
authorized, (b) require an active session cookie in addition to the key, or
(c) remove the "admin key returns all" branch entirely and require admin users
to use the authenticated web interface. At minimum, log every export request
with the caller identity and number of records returned.

---

### a01-cart-price-tampering · Tamper with the cart submission

**CWE-602 — Client-Side Enforcement of Server-Side Security**

**What it is.** The server trusts a value that was sent by the client — in this
case the unit price of items in the shopping cart — instead of re-reading the
canonical value from the database at checkout.

**How it works here.** `POST /cart/checkout` in
[cart.go](../internal/handlers/cart.go) reads `unit_price_{id}` and `qty_{id}`
from the posted form body and uses those values to compute the manifest total.
A crew member who intercepts the request (via a proxy like Burp Suite) and
edits the hidden form fields can pay an arbitrarily low price.

**Why this matters.** Any business-logic invariant enforced only in the browser
can be bypassed. This pattern causes real monetary loss in e-commerce
applications.

**Where it commonly appears.** Checkout flows that serialize cart state into
hidden HTML form fields, price-quoting APIs where the client POSTs the final
price, and any workflow where the browser is expected to "remember" a
server-derived value.

**How to find it.** Add items to a cart, open browser DevTools or a proxy,
intercept the checkout POST, and modify a `unit_price_*` field to `1` before
forwarding. Observe whether the manifest is created at the manipulated price.

**Fix for this implementation.** In `Cart.Checkout`, discard the client-supplied
price entirely. The canonical lines already live in `lines` (fetched from the
DB); use `l.realPrice` and `l.realQty` directly to build the manifest:

```go
items = append(items, ManifestItem{Name: l.name, Qty: l.realQty, UnitPrice: l.realPrice})
clientTotal += l.realPrice * l.realQty
```

Remove the `r.PostFormValue(priceKey)` / `r.PostFormValue(qtyKey)` blocks
entirely.

---

### a01-beacon-scan-internal-service · Scan an external beacon URL (SSRF — internal service)

**CWE-918 — Server-Side Request Forgery (SSRF)**

**What it is.** The server issues an HTTP request to a URL chosen by the user,
allowing the attacker to probe services that are reachable from the server
but not from the public internet.

**How it works here.** `GET /bridge/beacon-scan?url=<target>` in
[beacon.go](../internal/handlers/beacon.go) calls `beaconFetch(target)` with no
allowlist, no scheme restriction, and no IP filtering. Submitting a private-range
or loopback address (e.g., `http://192.168.1.1/`, `http://localhost:8080/`) causes
the application server to fetch it and return the response body to the crew
member.

**Why this matters.** SSRF enables network pivot attacks: attackers reach
internal APIs, admin interfaces, and metadata services that are invisible from
the public internet. In cloud environments it is the primary path to credential
theft via the IMDS.

**Where it commonly appears.** URL-fetch features (link preview, webhook
testing, image-from-URL upload), PDF generators, and any feature that accepts
a URL and makes a server-side request.

**How to find it.** Supply a URL pointing to an internal address
(`http://169.254.169.254/`, `http://10.0.0.1/`) or loopback. Observe whether
the server returns a response body that only the server itself could reach.

**Fix for this implementation.** After parsing the URL, resolve the hostname to
an IP and reject private / loopback / link-local ranges before making the
request. A strict allowlist (scheme must be `https`, hostname must resolve to a
public routable IP) is safer than a blocklist:

```go
parsed, _ := url.Parse(target)
if isPrivateOrLoopback(parsed.Hostname()) {
    http.Error(w, "forbidden target", http.StatusForbidden)
    return
}
```

---

### a01-beacon-cloud-metadata · Reach the cloud metadata endpoint (SSRF — IMDS)

**CWE-918 — Server-Side Request Forgery (SSRF)**

**What it is.** A specialization of SSRF where the attacker routes the
server-side request to the cloud Instance Metadata Service (IMDS) to harvest
instance identity, IAM role credentials, or user-data secrets.

**How it works here.** Same `beaconFetch` path as above. The `beaconFetch`
function even sets `Metadata-Flavor: Google` to ensure GCP IMDS responses work.
Submitting `http://169.254.169.254/latest/meta-data/` (AWS) or
`http://metadata.google.internal/computeMetadata/v1/` (GCP) triggers the
`isCloudMetadataHost` branch and flips this tracker.

**Why this matters.** IMDS metadata theft has been exploited in several
high-profile cloud breaches (Capital One 2019, etc.) to escalate from SSRF to
full account compromise via harvested IAM credentials.

**Where it commonly appears.** Any SSRF surface deployed on a cloud host
without IMDS IMDSv2 enforcement or a metadata-route block.

**How to find it.** From an SSRF surface, target `http://169.254.169.254/` and
observe whether the server returns an AWS/GCP/Azure metadata response.

**Fix for this implementation.** Same as above — block private/link-local
addresses. Additionally, enforce IMDSv2 (require a signed token header) on
the cloud instance itself so even a compromised server cannot retrieve
credentials via the old v1 endpoint.

---

### a01-beacon-loopback-admin · Bounce the beacon at the admin loopback (SSRF — loopback admin)

**CWE-918 — Server-Side Request Forgery (SSRF)**

**What it is.** A loopback-targeted SSRF where the server-side fetch reaches an
admin-only interface bound to `127.0.0.1` that is inaccessible from the network.

**How it works here.** The `bodyLooksAdmin` heuristic in
[beacon.go](../internal/handlers/beacon.go) matches admin-panel keywords
(`"diagnostics"`, `"debug"`, `"station command"`) in the response body of a
loopback fetch. Pointing the scanner at `http://localhost/debug` (the exposed
diagnostics panel) satisfies both conditions: loopback host and admin-flavored
content.

**Why this matters.** Binding admin interfaces to loopback is a common
partial mitigation; SSRF breaks that mitigation entirely by using the application
itself as a proxy.

**Where it commonly appears.** Internal admin dashboards, monitoring agents
(Prometheus node-exporter, etc.), database admin UIs (phpMyAdmin bound to
localhost), and any service that trusts the loopback interface.

**Fix for this implementation.** Same SSRF fix: reject loopback targets at the
handler level before issuing the request.

---

## A02 — Security Misconfiguration

### a02-diagnostics-panel-exposed · Pry open the diagnostics panel

**CWE-489 — Active Debug Code**

**What it is.** A debug or diagnostic endpoint that was never removed from the
production build, exposing runtime internals, environment variables, and
credential hints to anyone who knows (or guesses) the URL.

**How it works here.** `GET /debug` in
[debug.go](../internal/handlers/debug.go) returns a plain-text dump with no
authentication. It includes Go runtime info, all environment variables, the full
crew username list, and hardcoded "default credentials" for the `command`
account.

**Why this matters.** Debug endpoints are a reconnaissance goldmine: they
enumerate users, reveal internal paths, and often disclose the very credentials
an attacker needs for the next step.

**Where it commonly appears.** `/debug`, `/info`, `/status`, `/health`,
`/actuator` (Spring Boot), `/_ah/` (Google App Engine), and vendor-specific
paths included in framework scaffolding.

**How to find it.** Directory brute-force (gobuster, feroxbuster) with a
wordlist of common debug paths. Observe whether any path returns structured
technical information without requiring a login.

**Fix for this implementation.** Delete the `/debug` route and `debug.go` from
the production build — or gate it behind `requireAdmin` and an IP allowlist.
Never ship endpoints that expose env vars, stack traces, or credential hints.
Use a secrets manager (Vault, AWS Secrets Manager) instead of env vars for
credentials so that even a leaked env dump doesn't expose usable secrets.

---

### a02-default-station-credentials · Sign in with default station credentials

**CWE-1392 — Use of Default Credentials**

**What it is.** A vendor-default or factory-default account (`command` /
`stationcommand`) that was seeded at install time and never changed, allowing
anyone who knows the documented defaults to log in with admin privileges.

**How it works here.** The `/debug` panel prints the default credentials in
plain text. The `command` user is seeded in the database by
[seed.go](../internal/seed/seed.go) with a bcrypt hash of `stationcommand`.
Logging in with those credentials grants admin access and flips the tracker via
`Command.Dashboard`.

**Why this matters.** Default credentials are indexed by search engines,
documented in public manuals, and tested by automated scanners. They are
responsible for a disproportionate share of network device and appliance
compromises.

**Where it commonly appears.** Network gear (routers, switches, cameras), SaaS
admin portals seeded with a demo account, containerized applications shipped
with a default `admin:admin`, and vendor-supplied VM images.

**How to find it.** Read any documentation, debug output, or source code for
credential hints. Try `admin/admin`, `admin/password`, product-name combinations,
and credentials found in the app's own source or config files.

**Fix for this implementation.** The seed script should either (a) generate a
random password and print it once to stdout during first-run initialization, or
(b) require the operator to supply the admin password via an environment variable
before seeding. The default account should not exist with a known password in
any environment.

---

### a02-verbose-stack-traces · Trigger a verbose telemetry dump

**CWE-209 — Generation of Error Message Containing Sensitive Information**

**What it is.** An unhandled exception or panic whose full stack trace — including
file paths, function names, and internal state — is written directly to the HTTP
response instead of being logged server-side.

**How it works here.** `GET /telemetry?cycle=overload` triggers a `panic()` in
[telemetry.go](../internal/handlers/telemetry.go). The global `Recover`
middleware catches it and writes the full Go `debug.Stack()` output plus request
metadata (method, URL, remote address, user-agent) into the 500 response body.

**Why this matters.** Stack traces reveal internal file paths (leaking directory
structure), function call chains (fingerprinting the framework and version), and
sometimes variable values — all useful for planning further attacks.

**Where it commonly appears.** Development-mode middleware left on in production
(Django `DEBUG=True`, Node.js unhandled promise rejections in Express), PHP
`display_errors = On`, and any custom exception handler that passes the raw
error object to the response.

**How to find it.** Send malformed input (wrong type, missing required fields,
oversized values, null bytes) to various endpoints and observe whether any
response contains file paths, line numbers, or a recognizable stack trace format.

**Fix for this implementation.** In `Recover`, replace the verbose response with
a generic 500 and keep the detailed information in the server log:

```go
log.Printf("recovered panic on %s %s: %v\n%s", r.Method, r.URL.Path, rec, stack)
w.WriteHeader(http.StatusInternalServerError)
http.Error(w, "an unexpected fault occurred", http.StatusInternalServerError)
```

Never include `stack`, `rec`, `r.RemoteAddr`, or `r.UserAgent()` in the
response body.

---

## A03 — Vulnerable and Outdated Components

### a03-deprecated-image-parser · Salvage from a deprecated image parser

**CWE-1104 — Use of Unmaintained Third-Party Components**

**What it is.** The application routes uploaded images through a retired
ImageMagick 6.9.2-era parser that is vulnerable to ImageTragick
(CVE-2016-3714), which allows remote command execution via crafted `push
graphic-context` / `url()` directives in an MVG or SVG payload.

**How it works here.** `POST /avatar/upload` in
[avatar.go](../internal/handlers/avatar.go) passes the uploaded file to
`parseLegacyAvatar`. The function accepts `.mvg`, `.svg`, and `.png` extensions
and evaluates MVG graphic-context directives. `containsImageTragickProbe`
checks for a CVE-2016-3714 proof-of-concept pattern (`push graphic-context` +
`url()` + the CVE identifier) and flips the tracker when found.

**Why this matters.** Outdated image-processing libraries are a persistent
high-severity attack surface. ImageTragick was weaponized within days of
disclosure in 2016 and affected thousands of production applications.

**Where it commonly appears.** Any feature that processes user-uploaded images
(avatars, product photos, document thumbnails) without version-pinning and
patching the underlying image library.

**How to find it.** Identify the image-processing library in use (version
disclosure in error messages, package manifests, known CVE databases). Craft a
minimal proof-of-concept payload for the relevant CVE and submit it via the
upload form.

**Fix for this implementation.** Replace the legacy parser with a maintained
library and keep it pinned to a current, patched version. Strip all metadata
(EXIF, IPTC, ICC profiles) before processing. Run image processing in an
isolated container or sandbox with no outbound network access and minimal
filesystem permissions.

---

### a03-known-cve-jwt · Exploit the known JWT library flaw

**CWE-347 — Improper Verification of Cryptographic Signature**

**What it is.** A JWT library (or custom implementation) that honors the
token's own `alg` header — allowing an attacker to set `alg: none` and omit
the signature, bypassing verification entirely. This is a well-documented class
of JWT vulnerability (CVE-2015-9235, and many later variants).

**How it works here.** `POST /shuttle/verify` in
[shuttle.go](../internal/handlers/shuttle.go) calls `verifyShuttleJWT`, which
reads the algorithm from the token's header. When `alg` is `"none"` the
`case "none":` branch returns the payload without checking any signature.
A crew member mints their own token with `{"alg":"none","typ":"JWT"}` as the
header and `{"admin":true}` in the payload, submits it, and receives admin
authority.

**Why this matters.** The `alg=none` bypass was one of the most widely
exploited JWT vulnerabilities and affected a number of popular libraries in
2015–2018. Trusting client-supplied algorithm choice undermines cryptographic
guarantees entirely.

**Where it commonly appears.** Any service that validates JWTs without pinning
the expected algorithm server-side. Common in SSO implementations, API gateway
token validation, and microservices that inherit algorithm selection from the
token itself.

**How to find it.** Capture a valid JWT. Decode the header, change `alg` to
`none`, re-encode, remove the signature segment (or leave an empty third
segment), and submit. Observe whether the server accepts the token.

**Fix for this implementation.** In `verifyShuttleJWT`, remove the `case
"none":` branch entirely, or explicitly reject it:

```go
case "none":
    return zero, "", fmt.Errorf("alg=none is not permitted")
```

Hard-code the expected algorithm server-side rather than reading it from the
token. Use a well-maintained JWT library (e.g., `golang-jwt/jwt`) that does
not accept `none` by default.

---

### a03-vulnerable-markdown · Leverage the vulnerable markdown renderer

**CWE-1104 — Use of Unmaintained Third-Party Components**

**What it is.** A custom or outdated markdown renderer that strips `<script>`
tags but fails to sanitize dangerous URL schemes (`javascript:`, `data:`) in
link and image syntax, enabling XSS via a sanitizer bypass.

**How it works here.** `renderVulnerableMarkdown` in
[comms.go](../internal/handlers/comms.go) strips `<script>` tags with a regex
and then expands `![alt](url)` into `<img src="url" alt="alt">` and
`[text](url)` into `<a href="url">text</a>` with no URL-scheme validation. A
payload like `[click](javascript:alert(1))` or
`![x](x" onerror="alert(1))` passes the sanitizer and executes in any viewer's
browser.

**Why this matters.** Markdown sanitizer bypasses are a recurring vulnerability
class; real-world examples include CVE-2018-3717 (marked), CVE-2021-44906, and
multiple GitHub markdown issues. They lead to stored XSS affecting all readers
of the content.

**Where it commonly appears.** Blog comment systems, issue trackers, chat
applications, and any feature that renders user-supplied markdown.

**How to find it.** Submit markdown payloads containing `javascript:` URLs in
link and image syntax, event-handler attributes injected into image URLs, and
`data:text/html` URIs. Observe whether the rendered output executes.

**Fix for this implementation.** After expanding markdown to HTML, pass the
output through a proper HTML sanitizer (e.g., `bluemonday`) configured to
allowlist safe tags and explicitly block `javascript:`, `data:`, and
event-handler attributes. Better still, use a maintained markdown library with
built-in sanitization rather than the home-grown `renderVulnerableMarkdown`.

---

## A04 — Insecure Design / Cryptographic Failures

### a04-comms-beacon-cipher · Crack the comms beacon cipher

**CWE-327 — Use of a Broken or Risky Cryptographic Algorithm**

**What it is.** A homegrown MAC scheme that XORs two truncated SHA-1 digests
using a short, guessable shared secret — neither a standard algorithm nor
keyed with a sufficiently random secret.

**How it works here.** `signCommsBeacon` in
[comms_beacon.go](../internal/handlers/comms_beacon.go) computes
`SHA1(secret|ts|msg) XOR SHA1(ts|msg|secret)`, takes the first 10 bytes, and
hex-encodes the result. The secret is `"orbit"`. The page publishes the
algorithm spec and sample beacons, so an attacker can reproduce the MAC for
any candidate secret offline. A dictionary attack or brute force of short
strings cracks it in well under a second.

**Why this matters.** Rolling custom cryptographic primitives, even from
well-regarded hash functions, almost always produces a weaker scheme than
HMAC-SHA256. Short secrets compound the problem: a 5-character ASCII secret
has a search space of ~916 million, exhaustible in seconds on a modern laptop.

**Where it commonly appears.** Webhook signature schemes, inter-service request
signing, IoT device firmware signing, and any system where engineers implement
"lightweight" crypto without using the standard library's HMAC.

**How to find it.** Read the published signing specification. Identify the
algorithm family. Write or find an offline cracking tool that iterates likely
secrets (dictionary words, short strings) and checks each against a known
message/signature pair.

**Fix for this implementation.** Replace `signCommsBeacon` with
`hmac.New(sha256.New, secret)` using a cryptographically random key of at
least 32 bytes stored in a secrets manager. The `Verify` endpoint should use
`hmac.Equal` for constant-time comparison. Never publish the signing algorithm
and a set of known-good message/signature pairs together — that combination
enables offline cracking regardless of algorithm strength.

---

### a04-rememberme-plaintext · Decode the remember-me beacon token

**CWE-315 — Cleartext Storage of Sensitive Information in a Cookie**

**What it is.** A "remember me" cookie whose value is `base64(username:station_key)` —
encoded, not encrypted or signed — so anyone who reads the cookie (via
browser DevTools, XSS, or network interception) immediately has usable
credentials.

**How it works here.** `Auth.Login` in [auth.go](../internal/handlers/auth.go)
sets the `oe_remember` cookie with `base64.StdEncoding.EncodeToString([]byte(username+":"+stationKey))`.
The cookie is flagged `HttpOnly: false` (intentionally readable from JavaScript).
`GET /remember-me` decodes the cookie and prints the plaintext credentials.

**Why this matters.** Base64 is an encoding, not encryption. Any party that
captures the cookie value — via XSS, network sniffing on unencrypted HTTP, or
physical access to the browser — instantly has the cleartext credentials.

**Where it commonly appears.** Legacy "stay signed in" implementations, JWT
"refresh tokens" stored in non-HttpOnly cookies, and any session token whose
value encodes user identity without encryption.

**How to find it.** Sign in with "remember me" checked. Open browser DevTools →
Application → Cookies. Observe the cookie value. Base64-decode it.

**Fix for this implementation.** Replace the cookie value with an opaque random
token (e.g., `crypto/rand` 32-byte hex string) mapped to the user in a
`remember_me_tokens` database table. The cookie should be `HttpOnly: true`,
`Secure: true`, and `SameSite: Strict`. The token table should have an
expiration column and be cleaned up on logout.

---

### a04-weak-password-hash · Reverse a legacy crew password hash

**CWE-916 — Use of Password Hash With Insufficient Computational Effort**

**What it is.** Password hashes stored using MD5 — a fast, unsalted,
cryptographically broken algorithm — that can be reversed by looking up the
hash in a rainbow table or running a trivial dictionary attack.

**How it works here.** `GET /archive` in [legacy.go](../internal/handlers/legacy.go)
lists legacy crew records with their `md5_hash` values visible on the page.
`POST /archive/verify` accepts a username and plaintext, computes `md5(plaintext)`,
and compares it to the stored hash. MD5 has no salt and no computational cost,
so common passwords (and many others) exist in pre-computed rainbow tables.

**Why this matters.** MD5 can be computed at billions of hashes per second on
consumer GPUs. A database leak instantly translates to cracked passwords for
any user with a common or dictionary-derived password, enabling credential
stuffing across other services.

**Where it commonly appears.** Legacy PHP applications (`md5($password)`),
older MySQL `PASSWORD()` function, CMS databases predating bcrypt adoption,
and migration targets that never upgraded their hash scheme.

**How to find it.** Obtain hash values (IDOR, SQL injection, database dump).
Submit them to online lookup services (CrackStation, Hashes.org) or run
Hashcat/John the Ripper with a rockyou wordlist.

**Fix for this implementation.** The current (non-legacy) auth path correctly
uses bcrypt at cost 12. The legacy archive should be migrated:

1. On the next login by each legacy user, accept their plaintext password, verify
   it against the MD5 hash one final time, then immediately re-hash with bcrypt
   and update the `users.password_hash` column.
2. After migration, delete the `legacy_users` table and the `/archive` routes
   entirely.

Never expose raw hash values in any UI.

---

## A05 — Injection

### a05-requisition-search-sqli · Spike the requisition query

**CWE-89 — SQL Injection**

**What it is.** User input is concatenated directly into a SQL query string
instead of being passed as a bound parameter, allowing an attacker to alter
the query's structure.

**How it works here.** `Catalog.List` in
[catalog.go](../internal/handlers/catalog.go) builds the search query by string
interpolation:

```go
query = `... WHERE name LIKE '%` + search + `%' OR description LIKE '%` + search + `%' ...`
```

A search term like `%' UNION SELECT id,username,username,password_hash,0,0
FROM users--` appends a `UNION` clause that returns data from the `users` table
instead of (or in addition to) product rows.

**Why this matters.** SQL injection is the canonical injection vulnerability.
Depending on database permissions it enables data exfiltration, authentication
bypass, and (on some DBs) OS command execution.

**Where it commonly appears.** Search forms, filter parameters, login fields,
and any other user-controlled string that flows into a SQL string by
concatenation in legacy or careless code.

**How to find it.** Append a single quote to the search term. Observe whether
the app returns a database error (confirms string interpolation). Craft
`' OR '1'='1` and `' UNION SELECT NULL,NULL,...--` payloads to confirm
exploitability.

**Fix for this implementation.** Use parameterized queries for the search path.
Replace the string-built query with:

```go
query = `SELECT ... FROM products WHERE name LIKE ? OR description LIKE ? ORDER BY ...`
term := "%" + search + "%"
rows, err = c.DB.Query(query, term, term)
```

Never interpolate user input into SQL strings.

---

### a05-login-sqli · Slip past the badge reader

**CWE-89 — SQL Injection**

**What it is.** A login bypass via SQL injection: the WHERE clause built by
string concatenation can be trivially made to evaluate as `TRUE` for any row,
granting unauthenticated access.

**How it works here.** `Badge.Submit` in [badge.go](../internal/handlers/badge.go)
uses `fmt.Sprintf` to build the query:

```go
query := fmt.Sprintf(
    `SELECT id, username, is_admin FROM users WHERE username = '%s' AND station_key = '%s' LIMIT 1`,
    callsign, badge,
)
```

Submitting `callsign = command' --` with any `badge` value produces:

```sql
... WHERE username = 'command' --' AND station_key = '...' LIMIT 1
```

The `--` comments out the station-key check; the query returns the `command`
admin row unconditionally.

**Why this matters.** Login bypass is the most severe consequence of SQLi:
complete authentication circumvention with no knowledge of any password.

**Where it commonly appears.** Anywhere credentials are verified by a raw SQL
query built from user input: login pages, PIN entry forms, API key validation.

**How to find it.** Enter `' OR '1'='1` or `anything' --` in the username field
with any password. Observe whether authentication succeeds.

**Fix for this implementation.** Identical fix to the catalog search: use
parameterized queries:

```go
err := b.DB.QueryRow(
    `SELECT id, username, is_admin FROM users WHERE username = ? AND station_key = ? LIMIT 1`,
    callsign, badge,
).Scan(&id, &uname, &isAdmin)
```

---

### a05-comms-stored-xss · Inject a payload into the comms log

**CWE-79 — Cross-Site Scripting (Stored)**

**What it is.** A stored XSS: user-supplied content is persisted to the database
and later rendered as raw HTML in other users' browsers, executing attacker-
controlled JavaScript.

**How it works here.** `Comms.List` in [comms.go](../internal/handlers/comms.go)
renders comms entries with format `"raw"` using `template.HTML(bodyStr)` —
bypassing Go's `html/template` auto-escaping. A comms entry submitted with
`<script>alert(document.cookie)</script>` executes in every crew member's
browser when they load `/comms`.

**Why this matters.** Stored XSS persists until the entry is deleted and fires
for every user who views the page — enabling cookie theft, credential harvesting,
and session hijacking at scale.

**Where it commonly appears.** Comment systems, message boards, any feature
that stores and re-renders user text without sanitization.

**How to find it.** Submit `<script>alert(1)</script>` or
`<img src=x onerror=alert(1)>` in a text field. Navigate to the page that
renders stored entries (often as a different user). Observe whether the script
executes.

**Fix for this implementation.** Remove the `template.HTML()` cast. Let
`html/template` escape the content automatically:

```go
// Replace:
e.Body = template.HTML(bodyStr)

// With (storing as string and using a string field in CommsEntry):
e.BodyText = bodyStr
```

Then in the template use `{{.BodyText}}` (auto-escaped) instead of
`{{.Body}}`. If rich text is genuinely needed, use a strict allowlist sanitizer
(e.g., bluemonday) before casting to `template.HTML`.

---

## A06 — Vulnerable and Outdated Components / Security Design Flaws

### a06-allocation-race · Race the supply allocation gate

**CWE-367 — Time-of-Check Time-of-Use (TOCTOU) Race Condition**

**What it is.** The server reads a state value (stock remaining, has-claimed
flag), makes a decision based on it, and writes the result — but the three
steps are not atomic. A second concurrent request can pass the same read-phase
check before the first write commits, causing the system to over-allocate.

**How it works here.** `Supply.Claim` in [supply.go](../internal/handlers/supply.go)
(1) reads `remaining`, (2) reads `prior claim count`, (3) sleeps 75 ms, then
(4) inserts a claim and decrements remaining. With no transaction or row lock,
two simultaneous POST requests from the same user (or across users) both pass
the gate checks in the window opened by the sleep.

**Why this matters.** Race conditions in checkout and allocation flows cause
real financial loss (over-claiming limited-edition items, negative inventory,
double-spending).

**Where it commonly appears.** Shopping carts with limited stock, ticket booking
systems, coupon redemption, any "claim once" feature without database-level
uniqueness enforcement.

**How to find it.** Send 5–10 concurrent POST requests to the claim endpoint
within the same second (e.g., `xargs -P 10 curl ...`). Observe whether multiple
claims are recorded for a single user or whether remaining drops below zero.

**Fix for this implementation.** Two complementary fixes:

1. Wrap the read + write in a transaction with a database-level lock, or use
   a conditional `UPDATE ... WHERE remaining > 0` that returns rows-affected to
   detect exhaustion.
2. Add a `UNIQUE(drop_id, user_id)` constraint to `supply_claims` so the INSERT
   fails on a duplicate rather than silently succeeding.

Remove the artificial `time.Sleep`.

---

### a06-password-reset-flow · Reuse a password-reset token

**CWE-640 — Weak Password Recovery Mechanism for Forgotten Password**

**What it is.** A password-reset token that is not invalidated after first use,
allowing the same token to be replayed indefinitely to set the account password
to arbitrary values.

**How it works here.** `Reset.Confirm` in [reset.go](../internal/handlers/reset.go)
validates the token (exists + not expired), updates the password, and increments
`use_count` — but never deletes the token or marks it spent. Submitting the
same token a second time succeeds again.

**Why this matters.** If an attacker intercepts or guesses a reset token
(via phishing, log access, or brute force), a reusable token gives them an
unlimited window to reset the victim's password even after the victim has
already used the link.

**Where it commonly appears.** Legacy password-reset flows, email-verification
links, invitation links — any single-use token whose invalidation was
overlooked.

**How to find it.** Complete a password reset. Copy the token from the confirm
URL. Reset the password again using the same token. Observe whether the second
reset succeeds.

**Fix for this implementation.** After a successful reset, delete the token row
(or set a `used_at` timestamp and reject reuse):

```go
// After the password UPDATE:
if _, err := rs.DB.Exec(`DELETE FROM password_resets WHERE token = ?`, token); err != nil {
    log.Printf("reset confirm delete token: %v", err)
}
```

---

### a06-promo-code-replay · Replay a single-use ration voucher

**CWE-294 — Authentication Bypass by Capture-and-Replay**

**What it is.** A promotional code that is validated for existence but never
marked as redeemed, allowing the same code to be applied multiple times to
accumulate unlimited discounts.

**How it works here.** `Cart.ApplyVoucher` in [cart.go](../internal/handlers/cart.go)
looks up the voucher code in the `vouchers` table, confirms it exists, and
appends it to the session's applied-voucher list — but never sets a
`redeemed_at` column or deletes the row. Submitting the same code again adds
another discount to the session total.

**Why this matters.** Unrestricted coupon replay is a direct revenue loss
vector; in B2C applications it can be automated to generate near-zero checkout
totals.

**Where it commonly appears.** Promo code systems, gift card redemption, loyalty
point conversion — any "code for discount" feature without a `used` flag.

**How to find it.** Apply a voucher code. Submit the same code again from the
same session. Observe whether the discount doubles.

**Fix for this implementation.** Add a `redeemed_by` (user_id) and `redeemed_at`
column to the `vouchers` table. In `ApplyVoucher`, check for a prior redemption
before applying. Alternatively, insert a row into a separate `voucher_redemptions`
table and reject duplicates at the database level with a `UNIQUE(code, user_id)`
constraint.

---

## A07 — Identification and Authentication Failures

### a07-session-fixation · Hijack a session via fixation

**CWE-384 — Session Fixation**

**What it is.** The application does not rotate the session token on
authentication, so a pre-login session ID assigned to the browser remains valid
after sign-in. An attacker who plants a known session ID in the victim's browser
before they log in can use that same ID to assume the victim's authenticated
session.

**How it works here.** `Auth.Login` in [auth.go](../internal/handlers/auth.go)
intentionally omits `a.Session.RenewToken(r.Context())`. The session token in
place before the POST `/login` is the same token in place after it. `Auth.Register`
correctly calls `RenewToken` — the asymmetry is the planted lesson.

**Why this matters.** Session fixation lets an attacker authenticate as a victim
without ever knowing their password, using only a pre-established session
identifier.

**Where it commonly appears.** Login handlers that reuse session storage
initialized for unauthenticated browsing, frameworks where session ID rotation
is opt-in, and single-sign-on flows that pass session tokens in URLs.

**How to find it.** Note the `Set-Cookie` session value before submitting the
login form. Submit valid credentials. Compare the session cookie value before
and after login. If it is unchanged, the endpoint is vulnerable.

**Fix for this implementation.** Add `a.Session.RenewToken(r.Context())` at the
top of `Auth.Login`, before writing any session values:

```go
if err := a.Session.RenewToken(r.Context()); err != nil {
    http.Error(w, "internal error", http.StatusInternalServerError)
    return
}
```

---

### a07-no-rate-limit-login · Brute-force a crew password

**CWE-307 — Improper Restriction of Excessive Authentication Attempts**

**What it is.** The login endpoint does not throttle, lock, or challenge after
repeated failed authentication attempts, enabling an attacker to try an
unlimited number of passwords.

**How it works here.** `Auth.Login` in [auth.go](../internal/handlers/auth.go)
records failed attempts in `bruteForceTracker` (an in-memory map) and flips the
tracker row at threshold — but never adds any delay, lockout, or CAPTCHA. The
map is also process-local and cleared on restart. Password enumeration at
thousands of requests per minute is unimpeded.

**Why this matters.** No rate limiting makes credential stuffing and dictionary
attacks against known usernames practical in minutes. Combined with weak
password requirements (next entry), common passwords fall quickly.

**Where it commonly appears.** Login endpoints, API key validation, OTP
verification — any authentication check without exponential backoff, lockout,
or CAPTCHA.

**How to find it.** Send 10+ POST requests to `/login` with the same username
and different passwords in rapid succession. Observe whether any slowdown,
lockout, or challenge response occurs.

**Fix for this implementation.** Options in increasing strength:

1. **Account lockout**: after N failures for a username within a window, lock
   the account for a cooldown period (stored in the database, not in-memory).
2. **Progressive delay**: return a `Retry-After` header and enforce a server-
   side sleep that grows exponentially with failure count.
3. **CAPTCHA**: present a challenge after 3–5 failures.
4. **IP-based throttling**: rate-limit at the reverse proxy level (nginx `limit_req`).

In-memory counters (the current approach) reset on restart and provide no
protection in a multi-instance deployment.

---

### a07-weak-password-policy · Register with a trivial passphrase

**CWE-521 — Weak Password Requirements**

**What it is.** The registration form accepts passwords with no minimum length,
no complexity requirement, and no check against common-password lists, allowing
users to register with passwords like `password` or `123456`.

**How it works here.** `validateRegistration` in [auth.go](../internal/handlers/auth.go)
enforces only character-set rules and a maximum length. `isTrivialPassphrase`
detects and flips the tracker for `"password"` and `"123456"` specifically, but
the registration itself succeeds — these passwords are accepted.

**Why this matters.** Weak passwords are the first thing a brute-force or
credential-stuffing attack exploits. A policy that accepts `password` means the
account can be compromised the moment an attacker tries the top-10 common
password list.

**Where it commonly appears.** Registration forms without a password-strength
meter, legacy systems with outdated minimum-length requirements (6+ characters
instead of NIST-recommended 8+), and any form that doesn't check against known
leaked password databases.

**How to find it.** Attempt to register with `password`, `123456`, and the site
name as the password. Observe whether registration succeeds.

**Fix for this implementation.** In `validateRegistration`, add minimum-length
and common-password checks:

```go
if len(password) < 8 {
    return "Passphrase must be at least 8 characters."
}
if isTrivialPassphrase(password) {
    return "That passphrase is too common. Choose something less predictable."
}
```

NIST SP 800-63B recommends checking submitted passwords against a list of
known-compromised passwords (the `Have I Been Pwned` k-anonymity API is a
practical option) and enforcing a minimum of 8 characters with no mandatory
complexity rules (which often produce predictable patterns like `P@ssw0rd`).

---

## A08 — Software and Data Integrity Failures

### a08-unsigned-cargo-import · Tamper with a cargo ledger import

**CWE-345 — Insufficient Verification of Data Authenticity**

**What it is.** A bulk-import endpoint that accepts a CSV file and inserts
whatever prices it contains with no signature, checksum, or canonical-price
validation. The file can be edited between export and import without detection.

**How it works here.** `CargoImport.Submit` in [cargo.go](../internal/handlers/cargo.go)
parses the uploaded CSV and inserts manifests at the prices in the file. The
`processCSV` function does compare imported prices to the catalog to set the
`tampered` flag — but only for tracker detection; the import proceeds regardless
and no error is returned to the user.

**Why this matters.** Unsigned import files are vulnerable to tampering in
transit (MITM) and at rest (malicious insider edits the file on disk). Supply
chain integrity attacks often exploit bulk-import paths that skip validation.

**Where it commonly appears.** ETL pipelines, inventory import tools, financial
data feeds, and any process that ingests a file-based artifact without verifying
its provenance.

**How to find it.** Download the sample CSV from `/bridge/cargo-import/sample`.
Edit a `unit_price` column to `1`. Upload the modified file. Observe whether
the manifests are created at the tampered price.

**Fix for this implementation.** Add an HMAC signature to the export:

1. When generating the sample CSV, compute `HMAC-SHA256(csv_content, server_secret)`
   and include it as a header row or a `Content-Digest` HTTP response header.
2. In `processCSV`, verify the signature before processing any rows. Reject
   the import if the signature is absent or invalid.

Alternatively, enforce server-side price validation: reject any row whose
`unit_price` differs from the catalog canonical price.

---

### a08-unsafe-deserialization · Pry open the unsafe deserialization path

**CWE-502 — Deserialization of Untrusted Data**

**What it is.** The server deserializes a user-controlled data structure
(a base64+JSON "pre-auth packet") and acts on the values inside it without
verifying that the values were issued by the server — enabling privilege
escalation by crafting a packet that asserts elevated roles.

**How it works here.** `PreAuth.Redeem` in [preauth.go](../internal/handlers/preauth.go)
base64-decodes and JSON-unmarshals the submitted `preauth_token`. If the decoded
`Role` field is `"station_command"` the handler grants admin-level bulk-override
authority. There is no HMAC, no signature, and no cross-check against the
session. Any crew member who decodes their own token, changes `"role":"crew"` to
`"role":"station_command"`, re-encodes, and submits gets elevated authority.

**Why this matters.** Deserialization vulnerabilities that allow role/privilege
escalation via crafted payloads are a class of critical flaw. In languages with
native object serialization (Java, PHP, Python pickle) they can also lead to
remote code execution.

**Where it commonly appears.** Session tokens, JWTs, signed cookies, API
request bodies that carry user-supplied "context" objects, and any feature that
reconstructs server-side state from client-supplied serialized data.

**How to find it.** Retrieve your own token from `/bridge/cargo-preauth/token`.
Base64-decode it. Inspect the JSON. Edit the `role` or `operation` fields to
privileged values. Re-encode and submit.

**Fix for this implementation.** Sign the packet with a server-side HMAC before
issuing it, and verify the signature in `Redeem` before trusting any field:

```go
// At issue time:
pkt.Sig = computeHMAC(pkt, serverSecret)

// At redeem time:
if !verifyHMAC(pkt, serverSecret) {
    http.Error(w, "invalid token signature", http.StatusForbidden)
    return
}
```

Alternatively, store issued packet IDs in the database with their authorized
role and look them up on redeem, ignoring the role field in the token entirely.

---

### a08-update-channel-unverified · Slip a forged update through the patch channel

**CWE-494 — Download of Code Without Integrity Check**

**What it is.** A software update mechanism that fetches a binary or manifest
from a URL without verifying its integrity (hash or signature), allowing a
man-in-the-middle or a URL-override to deliver arbitrary content as a
legitimate update.

**How it works here.** `PatchChannel.Apply` in [patch.go](../internal/handlers/patch.go)
accepts a crew-supplied `patch_url`, fetches it, computes the SHA-256 of the
received body, and displays whether it matches the expected hash — but applies
the patch regardless of whether they match. Supplying any URL the crew controls
delivers forged content that is marked "applied."

**Why this matters.** Unverified update channels are the backbone of software
supply chain attacks. SolarWinds, 3CX, and numerous other high-profile
incidents involved updates delivered without integrity verification.

**Where it commonly appears.** Auto-update clients that fetch over HTTP (no TLS
pinning), package managers that skip checksum verification, firmware update
endpoints that accept a URL parameter, and any CI/CD pipeline that pulls
artifacts without hash or signature checks.

**How to find it.** Identify the update endpoint and the `patch_url` parameter.
Host a file on a server you control. Submit your URL. Observe whether the server
fetches and "applies" your content without a hash-match check.

**Fix for this implementation.** In `PatchChannel.Apply`, gate the apply step
on the hash check:

```go
if !result.HashMatch {
    result.Applied = false
    result.Err = "integrity check failed — patch not applied"
    data["Result"] = result
    render(w, p.Views, "patch_channel", data)
    return
}
result.Applied = true
```

In production, use a cryptographic signature (e.g., `ed25519`) in addition to
a hash — hashes alone only detect accidental corruption, not intentional
tampering by a party who can also update the published hash.

---

## A09 — Security Logging and Monitoring Failures

### a09-comms-log-silent-delete · Wipe the comms log trail

**CWE-778 — Insufficient Logging**

**What it is.** A destructive admin action (deleting a comms entry) that writes
no audit record, leaving no trace that the deletion occurred or who performed
it.

**How it works here.** `Comms.Delete` in [comms.go](../internal/handlers/comms.go)
executes `DELETE FROM comms_entries WHERE id = ?` with no corresponding `INSERT`
into an audit log table. The code comment explicitly notes `// Intentionally NO audit log insert here.`

**Why this matters.** Without audit logging, post-incident forensics cannot
determine what was deleted, when, or by whom. Regulatory frameworks (SOC 2,
HIPAA, PCI-DSS) explicitly require audit trails for data deletion.

**Where it commonly appears.** Any admin or privileged action path in an
application without a dedicated audit log table: user deletion, record
modification, permission changes, and configuration updates.

**How to find it.** Perform a destructive action (delete a comms entry as
admin). Search the application for any mechanism that would record the
deletion (database table, log file, event stream). Confirm nothing was written.

**Fix for this implementation.** Before the `DELETE`, insert an audit row:

```go
_, _ = c.DB.Exec(
    `INSERT INTO audit_log (actor_id, action, target_type, target_id, occurred_at) VALUES (?, 'delete', 'comms_entry', ?, CURRENT_TIMESTAMP)`,
    user.ID, id,
)
```

The audit log table should be append-only (no UPDATE/DELETE permissions for
the application DB user) and should be shipped to an external log aggregator
so it cannot be wiped by an attacker who also has admin access.

---

### a09-no-audit-on-privileged-action · Perform a privileged action with no trace

**CWE-778 — Insufficient Logging**

**What it is.** A role-escalation action (toggling a crew member's admin status)
that silently modifies the database with no audit record.

**How it works here.** `Command.ToggleAdmin` in [command.go](../internal/handlers/command.go)
executes `UPDATE users SET is_admin = ?` with an explicit comment:
`// VULNERABLE BY DESIGN: no audit log is written here.`

**Why this matters.** Privilege escalation is the most high-value action an
attacker can take. Without a log entry, a compromised admin account can silently
elevate a foothold account, and no trace of that escalation survives for
incident response.

**Where it commonly appears.** Admin portals that modify user roles, permission
changes in authorization systems, and any action that grants elevated access.

**Fix for this implementation.** Identical pattern to the comms-delete fix:
insert an audit row recording `actor_id`, the action (`grant_admin` /
`revoke_admin`), the target `user_id`, and a timestamp before returning the
redirect.

---

### a09-log-injection-newline · Forge a log entry via injection

**CWE-117 — Improper Output Neutralization for Logs**

**What it is.** User-supplied input is written to a log file verbatim, including
newline characters. An attacker who embeds `\n` in the input can insert
additional fake log lines that appear authentic to log-analysis tools.

**How it works here.** `Comms.Submit` in [comms.go](../internal/handlers/comms.go)
logs:

```go
log.Printf("comms: received transmission from %s (format=%s)", author, format)
```

The `author` field comes directly from the POST body. Submitting an author
value of `Alice\nINFO: admin promoted user Bob` produces two log lines: the
real one ending at the newline and a forged second line that looks like a
legitimate info log entry.

**Why this matters.** Log injection enables cover-track attacks (forging normal-
looking entries to hide malicious ones), SIEM evasion, and forensic
manipulation. Log files have implicit structural trust that is broken when user
input is written without escaping.

**Where it commonly appears.** Any code path that logs user-supplied strings
(usernames, comments, filenames, header values) without sanitizing control
characters.

**How to find it.** Submit a POST body with a newline in a logged field. Read
the server log. Observe whether a second, forged line appears.

**Fix for this implementation.** Strip or escape control characters before
logging:

```go
safeAuthor := strings.Map(func(r rune) rune {
    if r == '\n' || r == '\r' || r == '\t' {
        return ' '
    }
    return r
}, author)
log.Printf("comms: received transmission from %s (format=%s)", safeAuthor, format)
```

Alternatively, use a structured logger (e.g., `log/slog`) that serializes
fields as JSON, preventing injected newlines from creating new log records.

---

## A10 — Server-Side Request Forgery / Security Logging and Monitoring Failures

### a10-unchecked-exception-info-leak · Provoke an unchecked exception that leaks state

**CWE-209 — Generation of Error Message Containing Sensitive Information**

**What it is.** A decode error whose raw Go error message — including internal
struct field names, package paths, and expected types — is written directly into
the HTTP response.

**How it works here.** `LedgerCheck.Verify` in [ledger.go](../internal/handlers/ledger.go)
calls `dec.Decode(&entry)` and, on error, writes `err.Error()` to the response:

```go
fmt.Fprintf(w, "ledger parse error: %s\n", leaked)
```

A type mismatch (submitting `"qty":"four"` when `qty` expects an `int`)
produces a Go error like:
`json: cannot unmarshal string into Go struct field ledgerEntry.qty of type int`

This reveals the internal struct name (`ledgerEntry`), field name (`qty`), and
expected type (`int`) — useful for fingerprinting the application and mapping
its data model.

**Why this matters.** Internal error messages aid attackers in understanding
the application's data model, framework, and language — reducing the effort
needed to craft targeted payloads.

**Where it commonly appears.** API endpoints that echo raw database or
deserialization errors, exception handlers that forward `e.getMessage()` to the
client, and any middleware that converts unhandled exceptions to HTTP responses.

**How to find it.** Submit malformed JSON (wrong types, extra fields, null where
a number is expected) to API endpoints. Observe whether the response body
contains framework-specific error text.

**Fix for this implementation.**

```go
if err := dec.Decode(&entry); err != nil {
    log.Printf("ledger check decode: %v", err)  // log internally
    http.Error(w, "invalid payload", http.StatusBadRequest)  // generic to client
    return
}
```

Never surface raw error objects in API responses.

---

### a10-fail-open-authorization · Force an authorization check to fail open

**CWE-636 — Not Failing Securely ('Failing Open')**

**What it is.** An authorization check that, when it encounters an unexpected
error (e.g., a SQL parse error caused by injected input), falls through to grant
access rather than denying it.

**How it works here.** `RestrictedDossier.Page` in
[restricted_dossier.go](../internal/handlers/restricted_dossier.go) builds a
clearance-token lookup query via `fmt.Sprintf` (raw string interpolation). A
token value containing a single quote (e.g., `foo'`) produces broken SQL.
SQLite returns a parse error; the `if err != nil` branch logs the error and
then falls through to the protected content:

```go
if err != nil {
    log.Printf("clearance check error: %v", err)
    // intentional fall-through
}
```

**Why this matters.** Fail-open authorization is a particularly dangerous
design flaw because it grants access precisely when input is malformed — often
the same condition that indicates a probe or attack. The safe default for any
security check is "deny on error."

**Where it commonly appears.** Error handlers in authorization middleware, ACL
checks that catch exceptions broadly, and microservice permission checks that
treat a downstream service error as "permission indeterminate" and proceed.

**How to find it.** Supply input that is likely to cause the authorization check
to throw (SQL syntax error via injection, type mismatch, unexpected null). If
access is granted on error, the check fails open.

**Fix for this implementation.** Change the error branch to deny:

```go
if err != nil {
    log.Printf("restricted dossier clearance check error: %v", err)
    http.Error(w, "authorization check failed", http.StatusForbidden)
    return
}
```

Also fix the root cause: use a parameterized query instead of `fmt.Sprintf`
so the input cannot trigger a SQL error in the first place.

---

### a10-partial-rollback-on-error · Exploit a partially-rolled-back transaction

**CWE-460 — Improper Cleanup on Thrown Exception**

**What it is.** A multi-step database operation where the first write succeeds
and is committed, but the second write fails — and no rollback of the first
write occurs, leaving the system in an inconsistent intermediate state.

**How it works here.** `CargoBundle.Claim` in [bundle.go](../internal/handlers/bundle.go)
(1) inserts a manifest (`INSERT INTO manifests ...`) and (2) decrements the
bundle pool (`UPDATE cargo_bundles SET remaining = remaining - 1`). When
`remaining` is already 0 a `CHECK(remaining >= 0)` constraint fires on step 2,
returning an error. The manifest from step 1 was already committed; the error
handler does not delete it. The crew member holds a valid manifest even though
the bundle pool was exhausted.

**Why this matters.** Partial-write failures leave data in inconsistent states
that are difficult to detect and may have financial consequences (double
allocation, inventory discrepancy).

**Where it commonly appears.** Any sequence of related database writes that is
not wrapped in a transaction, especially in languages/frameworks where
transactions are opt-in (Go's `database/sql`, Django ORM, raw JDBC).

**How to find it.** Exhaust the resource (claim all bundles until `remaining = 0`).
Attempt one more claim. Observe whether a manifest is created despite the bundle
being empty.

**Fix for this implementation.** Wrap both writes in a transaction:

```go
tx, err := cb.DB.Begin()
if err != nil { /* handle */ }

// Step 1 (inside tx)
res, err := tx.Exec(`INSERT INTO manifests ...`, ...)
if err != nil { tx.Rollback(); /* handle */ }

// Step 2 (inside tx — rollback automatically undoes step 1 on error)
_, err = tx.Exec(`UPDATE cargo_bundles SET remaining = remaining - 1 WHERE id = ?`, bundle.ID)
if err != nil { tx.Rollback(); /* handle */ }

tx.Commit()
```

With both writes inside the same transaction, the constraint failure on step 2
causes `tx.Rollback()` to undo the manifest insert atomically.
