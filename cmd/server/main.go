// Orbital Exchange — purposefully-vulnerable training app entry point.
package main

import (
	"log"
	"net/http"

	"github.com/jshultz00/orbital-exchange/internal/config"
	"github.com/jshultz00/orbital-exchange/internal/db"
	"github.com/jshultz00/orbital-exchange/internal/handlers"
	"github.com/jshultz00/orbital-exchange/internal/seed"
	"github.com/jshultz00/orbital-exchange/internal/session"
	"github.com/jshultz00/orbital-exchange/internal/views"
)

func main() {
	cfg := config.Load()

	conn, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer conn.Close()
	log.Printf("db ready at %s", cfg.DBPath)

	if err := seed.All(conn); err != nil {
		log.Fatalf("seed: %v", err)
	}
	log.Print("seed: tracker + catalog applied")

	v, err := views.Load("views")
	if err != nil {
		log.Fatalf("views load: %v", err)
	}
	log.Print("views: templates loaded")

	sess := session.New(conn)

	// A "mux" (multiplexer / router) is a lookup table that matches each
	// incoming HTTP request to a handler based on its method + URL path.
	// Go 1.22+ ServeMux supports method-in-pattern syntax and {param} captures,
	// so we don't need a third-party router for an app this size.
	mux := http.NewServeMux()

	// Static assets — served from /static/ to avoid colliding with future routes.
	// StripPrefix removes "/static/" before the FileServer looks up the file,
	// so GET /static/css/theme.css reads ./public/css/theme.css from disk.
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("public"))))

	// Route syntax notes:
	//   "GET /{$}"            method + path; {$} anchors the match to EXACTLY "/"
	//                         (without it, "/" would match every path as a prefix).
	//   "GET /catalog/{slug}" {slug} is a path parameter — any single segment matches
	//                         and is readable via r.PathValue("slug") in the handler.
	pages := &handlers.Pages{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /{$}", pages.Landing)
	// Catch-all: any path that no more-specific pattern claims renders the
	// styled 404. The static handler ("/static/") and concrete routes are
	// all more specific than "/", so they still win.
	mux.HandleFunc("/", pages.NotFound)

	catalog := &handlers.Catalog{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /catalog", catalog.List)
	mux.HandleFunc("GET /catalog/{slug}", catalog.Detail)

	auth := &handlers.Auth{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /login", auth.LoginForm)
	mux.HandleFunc("POST /login", auth.Login)
	mux.HandleFunc("GET /register", auth.RegisterForm)
	mux.HandleFunc("POST /register", auth.Register)
	mux.HandleFunc("POST /logout", auth.Logout)

	// Planted vuln a06-password-reset-flow: the confirm handler validates
	// the reset token but never marks it spent, so a single token can reset
	// the password more than once.
	reset := &handlers.Reset{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /reset", reset.RequestForm)
	mux.HandleFunc("POST /reset", reset.Request)
	mux.HandleFunc("GET /reset/confirm", reset.ConfirmForm)
	mux.HandleFunc("POST /reset/confirm", reset.Confirm)

	// Planted vuln a03-known-cve-jwt: the shuttle-pass verifier honors the
	// token's own `alg` header — a token with `alg: none` bypasses the
	// signature check entirely.
	shuttle := &handlers.Shuttle{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /shuttle", shuttle.Page)
	mux.HandleFunc("POST /shuttle/verify", shuttle.Verify)
	// Planted vuln a04-rememberme-plaintext: /remember-me decodes the cookie
	// and reveals the plaintext payload (username + station_key).
	mux.HandleFunc("GET /remember-me", auth.RememberMe)

	// Planted vuln a05-login-sqli: the express badge reader builds its
	// lookup query by string concatenation, so the WHERE clause can be
	// short-circuited with the right input.
	badge := &handlers.Badge{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /badge", badge.Form)
	mux.HandleFunc("POST /badge", badge.Submit)

	cart := &handlers.Cart{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /cart", cart.View)
	mux.HandleFunc("POST /cart", cart.Add)
	mux.HandleFunc("POST /cart/{product_id}/remove", cart.Remove)
	// Planted vuln a06-promo-code-replay: voucher redemption validates the
	// code but never marks it spent, so a single code can be re-applied.
	mux.HandleFunc("POST /cart/voucher", cart.ApplyVoucher)
	// Planted vuln a01-cart-price-tampering: checkout reads per-line
	// unit_price and qty from hidden form fields without validating against
	// the canonical product price.
	mux.HandleFunc("POST /cart/checkout", cart.Checkout)

	manifest := &handlers.Manifest{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /manifest", manifest.Index)
	mux.HandleFunc("GET /manifest/export", manifest.Export)
	mux.HandleFunc("GET /manifest/{id}", manifest.Detail)

	crew := &handlers.Crew{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /crew", crew.Index)
	mux.HandleFunc("GET /crew/{id}", crew.Detail)

	comms := &handlers.Comms{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /comms", comms.List)
	mux.HandleFunc("POST /comms", comms.Submit)
	// Planted vuln a09-comms-log-silent-delete: admin deletes comms entries
	// with no audit row written.
	mux.HandleFunc("POST /comms/{id}/delete", comms.Delete)

	command := &handlers.Command{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /command", command.Dashboard)

	// Planted vuln a01-beacon-scan-*: SSRF via an unrestricted server-side
	// URL fetcher exposed to any logged-in crew member.
	beacon := &handlers.Beacon{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /bridge/beacon-scan", beacon.Scan)

	// Planted vuln a06-allocation-race: the supply-drop claim handler reads
	// remaining stock and "have you claimed?" then sleeps then writes —
	// outside a transaction, so concurrent POSTs can both pass the gate.
	supply := &handlers.Supply{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /bridge/supply-drop", supply.View)
	mux.HandleFunc("POST /bridge/supply-drop/claim", supply.Claim)

	tracker := &handlers.Tracker{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /tracker", tracker.View)
	mux.HandleFunc("POST /tracker/reset", tracker.Reset)
	mux.HandleFunc("POST /tracker/{id}/discover", tracker.Discover)

	// Planted vuln a02-diagnostics-panel-exposed: a debug route deliberately
	// shipped with no auth gate. Discovery flips the tracker row on first hit.
	debug := &handlers.Debug{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /debug", debug.Panel)

	// Planted vuln a02-verbose-stack-traces: /telemetry panics on bad input
	// and the global Recover middleware dumps the full stack into the response.
	telemetry := &handlers.Telemetry{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /telemetry", telemetry.Cycle)

	// Planted vuln a04-weak-password-hash: the decommissioned crew archive
	// dumps unsalted MD5 password digests and exposes a verifier that flips
	// the tracker when any plaintext is cracked.
	legacy := &handlers.Legacy{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /archive", legacy.Index)
	mux.HandleFunc("POST /archive/verify", legacy.Verify)

	// Planted vuln a04-comms-beacon-cipher: outbound beacons are signed by
	// a custom (non-HMAC) MAC routine with a short shared secret. The page
	// publishes the spec and recent beacons so the secret falls to offline
	// brute force; submitting it to the verifier flips the tracker.
	commsBeacon := &handlers.CommsBeacon{DB: conn, Views: v, Session: sess}
	mux.HandleFunc("GET /bridge/comms-beacon", commsBeacon.Page)
	mux.HandleFunc("POST /bridge/comms-beacon/verify", commsBeacon.Verify)

	// sess.LoadAndSave is the session middleware: it loads any existing
	// session for the request, makes session methods callable inside handlers
	// via r.Context(), and writes the updated session back on the way out.
	// Wrapping the whole mux means every route — static and dynamic — has
	// access to the session.
	log.Printf("orbital-exchange listening on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, handlers.Recover(conn, sess.LoadAndSave(mux))); err != nil {
		log.Fatalf("server: %v", err)
	}
}
