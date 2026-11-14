package api

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
)

// The human-readable API reference (ocidex-a0p4).
//
// It lives under /api because that prefix is the one every deployment already
// routes to this binary: the chart's HTTPRoute, the compose nginx and the vite
// dev proxy all send /api here and everything else to the web tier. huma's own
// /docs and /openapi.json sit outside it, so on a default install they were
// unreachable from a browser.
//
// The renderer is Scalar, vendored by scripts/vendor-scalar.sh and embedded, not
// loaded from a CDN: the reference keeps working in an air-gapped install, and
// the page's CSP can hold script-src and connect-src to 'self'. The connect-src
// is also what makes the configuration below a guarantee rather than a hope:
// telemetry, the hosted agent chat and the request proxy are all switched off,
// and the policy refuses them anyway if a future Scalar turns one back on.
const (
	apiDocsPath       = "/api/docs"
	apiDocsScriptPath = "/api/docs/scalar.js"
	apiSpecJSONPath   = "/api/openapi.json"
	apiSpecYAMLPath   = "/api/openapi.yaml"
	legacyDocsPath    = "/docs"
)

//go:embed apiref/scalar.js.gz
var scalarJSGzip []byte

//go:embed apiref/SCALAR_VERSION
var scalarVersion string

// apiDocsCSP governs the reference page only. 'unsafe-inline' styles are
// Scalar's requirement: it injects its theme as <style> elements at runtime.
// Fonts are the app's own Google Fonts pair, so the reference reads as OCIDex
// rather than as Scalar.
var apiDocsCSP = strings.Join([]string{
	"default-src 'none'",
	"base-uri 'none'",
	"script-src 'self'",
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
	"font-src https://fonts.gstatic.com",
	"img-src 'self' data:",
	"connect-src 'self'",
	"form-action 'none'",
	"frame-ancestors 'none'",
}, "; ")

// scalarConfig is the renderer configuration, written into the page as a
// data attribute. Keys are Scalar's (https://guides.scalar.com); an unknown key
// is ignored silently, so a Scalar bump needs a look at the page.
func scalarConfig() map[string]any {
	return map[string]any{
		"theme":                "default",
		"darkMode":             true,
		"layout":               "modern",
		"withDefaultFonts":     false,
		"telemetry":            false,
		"agent":                map[string]any{"disabled": true},
		"mcp":                  map[string]any{"disabled": true},
		"showDeveloperTools":   "never",
		"hideClientButton":     false,
		"persistAuth":          false,
		"defaultOpenAllTags":   false,
		"operationsSorter":     "method",
		"documentDownloadType": "both",
		"metaData":             map[string]any{"title": "OCIDex API Reference"},
		"authentication":       map[string]any{"preferredSecurityScheme": securitySchemeBearer},
		"customCss":            scalarThemeCSS,
	}
}

// scalarThemeCSS maps Scalar's tokens onto the app's (web/src/index.css), so
// colour means the same thing here as in the app: red is identity, blue is
// navigation and state. Keep the hex values in step with index.css.
const scalarThemeCSS = `
:root {
  --scalar-font: "Inter", system-ui, sans-serif;
  --scalar-font-code: "JetBrains Mono", ui-monospace, monospace;
  --scalar-custom-header-height: 48px;
  --scalar-radius: 6px;
  --scalar-radius-lg: 8px;
}
.dark-mode {
  --scalar-background-1: #0C0E14;
  --scalar-background-2: #161921;
  --scalar-background-3: #1E2230;
  --scalar-background-accent: rgba(91, 141, 239, 0.12);
  --scalar-border-color: #2A2E3E;
  --scalar-color-1: #E4E7F0;
  --scalar-color-2: #8B90A5;
  --scalar-color-3: #82879D;
  --scalar-color-accent: #5B8DEF;
  --scalar-sidebar-background-1: #0C0E14;
  --scalar-sidebar-item-hover-background: #1E2230;
  --scalar-sidebar-item-active-background: rgba(91, 141, 239, 0.12);
  --scalar-sidebar-color-active: #5B8DEF;
  --scalar-sidebar-border-color: #2A2E3E;
  --scalar-sidebar-search-background: #161921;
  --scalar-sidebar-search-border-color: #2A2E3E;
  --scalar-button-1: #DC3545;
  --scalar-button-1-hover: #E8525F;
  --scalar-button-1-color: #FFFFFF;
  --scalar-color-green: #34D399;
  --scalar-color-red: #F06565;
  --scalar-color-yellow: #FBBF24;
  --scalar-color-blue: #5B8DEF;
}
.light-mode {
  --scalar-background-1: #F8F6F1;
  --scalar-background-2: #FFFFFF;
  --scalar-background-3: #F3F1EC;
  --scalar-background-accent: rgba(29, 78, 216, 0.08);
  --scalar-border-color: #E0DDD5;
  --scalar-color-1: #1A1D27;
  --scalar-color-2: #5C6070;
  --scalar-color-3: #666B7A;
  --scalar-color-accent: #1D4ED8;
  --scalar-sidebar-background-1: #F8F6F1;
  --scalar-sidebar-item-hover-background: #F3F1EC;
  --scalar-sidebar-item-active-background: rgba(29, 78, 216, 0.08);
  --scalar-sidebar-color-active: #1D4ED8;
  --scalar-sidebar-border-color: #E0DDD5;
  --scalar-sidebar-search-background: #FFFFFF;
  --scalar-sidebar-search-border-color: #E0DDD5;
  --scalar-button-1: #CC1429;
  --scalar-button-1-hover: #B31020;
  --scalar-button-1-color: #FFFFFF;
}
`

// apiDocsFavicon is web/public/favicon.svg, inlined because the API does not
// serve the web tier's static files.
const apiDocsFavicon = `data:image/svg+xml,` +
	`%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E` +
	`%3Crect width='32' height='32' rx='6' fill='%231a1d27'/%3E` +
	`%3Ctext x='4' y='23' font-family='system-ui,sans-serif' font-size='16' font-weight='700' fill='%23e1e4ed'%3EO` +
	`%3Ctspan fill='%236c8aff'%3ED%3C/tspan%3E%3C/text%3E%3C/svg%3E`

// apiDocsHeaderCSS styles the OCIDex bar above the reference: the sidebar's
// red brand slab, laid flat, with the way back to the app. Its height is
// --scalar-custom-header-height, which Scalar offsets its sticky sidebar by.
const apiDocsHeaderCSS = `
html, body { margin: 0; }
.ocidex-bar {
  position: sticky; top: 0; z-index: 1000;
  height: 48px; box-sizing: border-box;
  display: flex; align-items: center; gap: 0.75rem;
  padding: 0 1.25rem;
  background: #DC3545; color: #FFFFFF;
  font-family: "Inter", system-ui, sans-serif;
}
.ocidex-bar .led { width: 6px; height: 6px; border-radius: 50%; background: #ffb020; flex-shrink: 0; }
.ocidex-bar .brand {
  margin: 0; font-family: "Space Grotesk", "Inter", sans-serif;
  font-size: 1.125rem; font-weight: 700; letter-spacing: -0.02em; color: #FFFFFF;
  text-decoration: none;
}
.ocidex-bar .brand span { font-weight: 400; }
.ocidex-bar .section { font-size: 0.875rem; font-weight: 500; opacity: 1; padding-left: 0.75rem; border-left: 1px solid rgba(255,255,255,0.45); }
.ocidex-bar .back {
  margin-left: auto; color: #FFFFFF; font-size: 0.875rem; font-weight: 500;
  text-decoration: none; padding: 0.375rem 0.75rem; border-radius: 6px;
  border: 1px solid rgba(255,255,255,0.55);
}
.ocidex-bar .back:hover { background: rgba(255,255,255,0.14); }
.ocidex-bar .back:focus-visible { outline: 2px solid #FFFFFF; outline-offset: 2px; }
body.light-mode .ocidex-bar { background: #CC1429; }
@media (max-width: 480px) { .ocidex-bar .section { display: none; } }
`

// apiDocsPage renders the reference shell. Everything interpolated is ours,
// but it is escaped anyway, since the configuration travels in an attribute.
func apiDocsPage() []byte {
	cfg, err := json.Marshal(scalarConfig())
	if err != nil {
		panic("marshal scalar config: " + err.Error())
	}
	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="strict-origin-when-cross-origin">
<title>OCIDex API Reference</title>
<link rel="icon" href="` + apiDocsFavicon + `">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Space+Grotesk:wght@500;700&display=swap">
<style>` + apiDocsHeaderCSS + `</style>
</head>
<body>
<header class="ocidex-bar">
  <span class="led" aria-hidden="true"></span>
  <a class="brand" href="/">OCI<span>Dex</span></a>
  <span class="section">API Reference</span>
  <a class="back" href="/">Back to OCIDex</a>
</header>
<script id="api-reference" data-url="` + apiSpecJSONPath + `" data-configuration="`)
	b.WriteString(html.EscapeString(string(cfg)))
	b.WriteString(`"></script>
<script src="` + apiDocsScriptPath + `?v=` + html.EscapeString(strings.TrimSpace(scalarVersion)) + `"></script>
</body>
</html>
`)
	return []byte(b.String())
}

// registerAPIReference mounts the reference page, its renderer and the /api
// copies of the spec. These are plain routes rather than huma operations: they
// describe the API, they are not part of it, so they stay out of the spec and
// out of the auth matrix. All of them are public, like the spec itself.
func registerAPIReference(r chi.Router, api huma.API) {
	page := apiDocsPage()

	r.Get(apiDocsPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", apiDocsCSP)
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(page)
	})
	r.Get(apiDocsPath+"/", redirectTo(apiDocsPath))
	r.Get(legacyDocsPath, redirectTo(apiDocsPath))

	r.Get(apiDocsScriptPath, serveScalarJS)

	var once sync.Once
	var specJSON, specYAML []byte
	var specErr error
	load := func() {
		spec := api.OpenAPI()
		if specJSON, specErr = json.Marshal(spec); specErr != nil {
			return
		}
		specYAML, specErr = spec.YAML()
	}
	serveSpec := func(contentType string, body *[]byte) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			once.Do(load)
			if specErr != nil {
				http.Error(w, "openapi spec unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write(*body)
		}
	}
	r.Get(apiSpecJSONPath, serveSpec("application/openapi+json", &specJSON))
	r.Get(apiSpecYAMLPath, serveSpec("application/openapi+yaml", &specYAML))
}

func redirectTo(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
}

// serveScalarJS serves the embedded bundle gzip-encoded, which is how it is
// stored, and inflates it only for the rare client that does not accept gzip.
// The URL carries the vendored version, so the response can be cached hard.
func serveScalarJS(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/javascript; charset=utf-8")
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Add("Vary", "Accept-Encoding")
	if acceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		_, _ = w.Write(scalarJSGzip)
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(scalarJSGzip))
	if err != nil {
		http.Error(w, "renderer unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = zr.Close() }()
	// G110 guards against inflating untrusted input; this is the bundle
	// embedded at build time by scripts/vendor-scalar.sh.
	_, _ = io.Copy(w, zr) //nolint:gosec // G110: trusted, embedded source
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, q, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(enc), "gzip") && strings.TrimSpace(q) != "q=0" {
			return true
		}
	}
	return false
}
