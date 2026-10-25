package api_test

import (
	"sort"
	"strings"
	"testing"
)

// TestOpenAPIPropertiesAreCamelCase enforces the 1.0 naming rule (ocidex-nps9.7,
// docs/API_VERSIONING.md): every JSON property under /api/v1 is camelCase. The
// snake_case ones were renamed before the compatibility freeze (ocidex-nps9.32);
// after it, a new one would be a contract break to undo, so it fails here.
func TestOpenAPIPropertiesAreCamelCase(t *testing.T) {
	h := newTestHandlerWithPinger(&fakeSBOMService{}, &fakeSearchService{}, &fakePinger{})
	_ = newTestRouterFromHandler(h)

	schemas := h.API().OpenAPI().Components.Schemas.Map()
	if len(schemas) < 50 {
		t.Fatalf("only %d schemas registered; the check would be vacuous", len(schemas))
	}
	var bad []string
	for name, schema := range schemas {
		for prop := range schema.Properties {
			if strings.Contains(prop, "_") {
				bad = append(bad, name+"."+prop)
			}
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("snake_case JSON properties in the API (use camelCase):\n  %s", strings.Join(bad, "\n  "))
	}
}
