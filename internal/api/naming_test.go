package api_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
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

// TestOpenAPIParametersAreCamelCase extends the rule to query and path
// parameter names, and to the values a `sort` parameter accepts, which name
// fields (ocidex-nps9.34).
func TestOpenAPIParametersAreCamelCase(t *testing.T) {
	h := newTestHandlerWithPinger(&fakeSBOMService{}, &fakeSearchService{}, &fakePinger{})
	_ = newTestRouterFromHandler(h)

	var bad []string
	for path, item := range h.API().OpenAPI().Paths {
		if strings.Contains(path, "_") {
			bad = append(bad, "path "+path)
		}
		for _, op := range []*huma.Operation{item.Get, item.Put, item.Post, item.Patch, item.Delete} {
			if op == nil {
				continue
			}
			for _, p := range op.Parameters {
				if strings.Contains(p.Name, "_") {
					bad = append(bad, op.OperationID+" param "+p.Name)
				}
				if p.Name == "sort" && p.Schema != nil {
					for _, v := range p.Schema.Enum {
						if s, ok := v.(string); ok && strings.Contains(s, "_") {
							bad = append(bad, op.OperationID+" sort value "+s)
						}
					}
				}
			}
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("snake_case names in the API (use camelCase):\n  %s", strings.Join(bad, "\n  "))
	}
}
