// Package recon enumerates URLs and endpoints worth probing.
//
// In Phase A this is a static seed list of Juice Shop endpoints. Phase B+
// will add light dynamic discovery (crawl the SPA's chunk manifest, parse
// the Swagger doc at /api-docs) — but a static list is good enough to
// exercise every check end-to-end first.
//
// LEARNING NOTE: real engagements always start with a manual endpoint
// inventory; an automatic crawler is a *supplement* to the manual list, not
// a replacement. This package preserves that ordering on purpose.
package recon

// Endpoint is one URL path the scanner knows about, with hints about what
// inputs it accepts. Checks use the hints to decide which payloads apply.
type Endpoint struct {
	Path        string
	Method      string
	Description string
	// Params lists query / form / JSON parameter names that look injectable.
	Params []string
	// AuthRequired hints that the endpoint expects an Authorization header.
	AuthRequired bool
}

// JuiceShopEndpoints is the seed list of Juice Shop endpoints used by the
// scanner. Keep this list small and curated; bigger is not better here
// because every entry multiplies the number of requests we make.
var JuiceShopEndpoints = []Endpoint{
	{Path: "/", Method: "GET", Description: "Frontend root (HTML, headers source of truth)"},
	{Path: "/rest/user/login", Method: "POST", Description: "Login endpoint", Params: []string{"email", "password"}},
	{Path: "/rest/products/search", Method: "GET", Description: "Product search", Params: []string{"q"}},
	{Path: "/api/Users", Method: "GET", Description: "Users collection (IDOR target)", AuthRequired: true},
	{Path: "/api/Products", Method: "GET", Description: "Products collection"},
	{Path: "/rest/basket/1", Method: "GET", Description: "Basket by ID (IDOR target)", AuthRequired: true},
	{Path: "/api/Recycles", Method: "GET", Description: "Recycles collection (IDOR target)", AuthRequired: true},
	{Path: "/api-docs", Method: "GET", Description: "Swagger UI (exposure check)"},
	{Path: "/ftp", Method: "GET", Description: "FTP-style listing (exposure check)"},
	{Path: "/ftp/", Method: "GET", Description: "FTP-style listing trailing slash"},
	{Path: "/metrics", Method: "GET", Description: "Prometheus metrics (exposure check)"},
	{Path: "/administration", Method: "GET", Description: "Admin panel (exposure check)"},
	{Path: "/package.json", Method: "GET", Description: "Dependency manifest (A06 fingerprint)"},
}
