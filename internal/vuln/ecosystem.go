package vuln

// purlTypeToEcosystems maps purl type tokens to one or more OSV ecosystem names used in
// the modified_id.csv URL path (e.g. "npm" → ["npm"], "apk" → ["Alpine","Wolfi","Chainguard"]).
// Multi-value types (apk, deb) include all ecosystems that share the purl type so that a
// Wolfi or Ubuntu advisory advancing its CSV is detected even if Alpine/Debian did not change.
// Types absent from this map are treated as unknown and always refreshed.
var purlTypeToEcosystems = map[string][]string{
	"npm":      {"npm"}, //nolint:goconst // "npm" appears as both key and value; test files add ≥3 more occurrences
	"pypi":     {"PyPI"},
	"maven":    {"Maven"},
	"golang":   {"Go"},
	"go":       {"Go"},
	"cargo":    {"crates.io"},
	"gem":      {"RubyGems"},
	"nuget":    {"NuGet"},
	"composer": {"Packagist"},
	"apk":      {"Alpine", "Wolfi", "Chainguard"}, //nolint:goconst // "Alpine" threshold crossed by test-file ecosystem-state maps
	"deb":      {"Debian", "Ubuntu"},
	"hex":      {"Hex"},
	"pub":      {"Pub"},
	"swift":    {"SwiftURL"},
	"cran":     {"CRAN"},
	"conan":    {"ConanCenter"},
	"bitnami":  {"Bitnami"},
}

// PurlTypeToOSVEcosystems returns the OSV ecosystem names for the given purl type.
// Returns (nil, false) for unknown types.
func PurlTypeToOSVEcosystems(purlType string) ([]string, bool) {
	ecos, ok := purlTypeToEcosystems[purlType]
	return ecos, ok
}
