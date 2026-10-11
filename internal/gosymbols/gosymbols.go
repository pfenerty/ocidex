// Package gosymbols defines how the function symbols linked into a Go binary
// travel inside a CycloneDX document and how their names are normalized
// (ADR-050).
//
// syft reads the symbols from a binary's pclntab but its CycloneDX encoder drops
// them, so ocidex carries them as component properties, one per import path:
//
//	name:  ocidex:go:symbols:<import path>
//	value: space-separated local symbol names (import path prefix stripped)
//
// An import path with an empty value is present with no symbols recorded;
// govulndb whole-package advisories depend on that distinction.
package gosymbols

import (
	"regexp"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// PropertyPrefix starts every symbol property name.
const PropertyPrefix = "ocidex:go:symbols:"

// Table maps an import path to the local symbol names linked from it.
type Table map[string][]string

// Properties encodes t as CycloneDX properties, sorted by import path.
func Properties(t Table) []cdx.Property {
	paths := make([]string, 0, len(t))
	for p := range t {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	out := make([]cdx.Property, 0, len(paths))
	for _, p := range paths {
		names := append([]string(nil), t[p]...)
		sort.Strings(names)
		out = append(out, cdx.Property{Name: PropertyPrefix + p, Value: strings.Join(names, " ")})
	}
	return out
}

// FromProperties extracts the symbol table carried by props (nil if none) and
// returns the remaining properties.
func FromProperties(props []cdx.Property) (Table, []cdx.Property) {
	var t Table
	rest := props[:0:0]
	for _, p := range props {
		path, ok := strings.CutPrefix(p.Name, PropertyPrefix)
		if !ok || path == "" {
			rest = append(rest, p)
			continue
		}
		if t == nil {
			t = Table{}
		}
		t[path] = append(t[path], strings.Fields(p.Value)...)
	}
	return t, rest
}

// Strip removes symbol properties from every component of bom, recursively, and
// reports whether it removed any. Ingest stores symbols relationally, so the
// persisted document does not carry them twice.
func Strip(bom *cdx.BOM) bool {
	if bom == nil || bom.Components == nil {
		return false
	}
	var changed bool
	var walk func(comps []cdx.Component)
	walk = func(comps []cdx.Component) {
		for i := range comps {
			c := &comps[i]
			if c.Properties != nil {
				if t, rest := FromProperties(*c.Properties); t != nil {
					changed = true
					if len(rest) == 0 {
						c.Properties = nil
					} else {
						c.Properties = &rest
					}
				}
			}
			if c.Components != nil {
				walk(*c.Components)
			}
		}
	}
	walk(*bom.Components)
	return changed
}

var typeParams = regexp.MustCompile(`\[[^]]*]`)

// Normalize converts a local symbol name as it appears in a binary's symbol table
// into govulndb's naming convention, the vocabulary vulnerabilities are matched
// and queried in: pointer-receiver decoration is removed ("(*T).M" → "T.M"),
// generic instantiations lose their type parameters, and the "-fm"
// method-value-wrapper suffix is dropped (its presence means the method is used).
// It mirrors grype's provider-side normalization, which a symbol table attached
// by hand must already have had applied.
func Normalize(name string) string {
	if strings.IndexByte(name, '(') >= 0 {
		name = strings.ReplaceAll(name, "(*", "")
		name = strings.ReplaceAll(name, ")", "")
	}
	name = strings.TrimSuffix(name, "-fm")
	if strings.IndexByte(name, '[') >= 0 {
		name = typeParams.ReplaceAllString(name, "")
	}
	return name
}

// Normalized returns a copy of t with every name normalized and de-duplicated per
// import path, sorted. Import paths with no names are kept (present, empty).
func Normalized(t Table) Table {
	if t == nil {
		return nil
	}
	out := make(Table, len(t))
	for path, names := range t {
		seen := make(map[string]bool, len(names))
		norm := make([]string, 0, len(names))
		for _, n := range names {
			n = Normalize(n)
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			norm = append(norm, n)
		}
		sort.Strings(norm)
		out[path] = norm
	}
	return out
}
