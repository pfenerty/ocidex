package vuln

// purlTypeToEcosystem maps purl type tokens to OSV ecosystem names used in
// the modified_id.csv URL path (e.g. "npm" → "npm", "pypi" → "PyPI").
// Types absent from this map are treated as unknown and always refreshed.
var purlTypeToEcosystem = map[string]string{
	"npm":      "npm", //nolint:goconst // "npm" key+value string appears >3x across test files
	"pypi":     "PyPI",
	"maven":    "Maven",
	"golang":   "Go",
	"go":       "Go",
	"cargo":    "crates.io",
	"gem":      "RubyGems",
	"nuget":    "NuGet",
	"composer": "Packagist",
	"apk":      "Alpine",
	"deb":      "Debian",
	"hex":      "Hex",
	"pub":      "Pub",
	"swift":    "SwiftURL",
}

// PurlTypeToOSVEcosystem maps a purl type token to its OSV ecosystem name.
// Returns ("", false) for unknown types.
func PurlTypeToOSVEcosystem(purlType string) (string, bool) {
	eco, ok := purlTypeToEcosystem[purlType]
	return eco, ok
}
