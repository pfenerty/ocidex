package main

import (
	"bytes"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/matryer/is"
)

func collect(t *testing.T, spec Spec) []SBOM {
	t.Helper()
	var out []SBOM
	if err := Generate(spec, func(s SBOM) error { out = append(out, s); return nil }); err != nil {
		t.Fatalf("generate: %v", err)
	}
	return out
}

var smallSpec = Spec{Seed: 7, Artifacts: 4, Versions: 5, Components: 60, BaseImages: 2, BaseShare: 0.4, Churn: 0.05}

func TestGenerateIsDeterministic(t *testing.T) {
	is := is.New(t)
	a, b := collect(t, smallSpec), collect(t, smallSpec)
	is.Equal(len(a), 4*5)
	for i := range a {
		is.True(bytes.Equal(a[i].Doc, b[i].Doc))
	}
	other := smallSpec
	other.Seed = 8
	is.True(!bytes.Equal(collect(t, other)[1].Doc, a[1].Doc))
}

func TestGenerateShape(t *testing.T) {
	is := is.New(t)
	sboms := collect(t, smallSpec)

	versions := map[string]map[string]string{} // artifact -> purl set of its first version
	digests := map[string]bool{}
	for _, s := range sboms {
		var bom cdx.BOM
		is.NoErr(json.Unmarshal(s.Doc, &bom))
		is.Equal(len(*bom.Components), 60)
		is.True(bom.Dependencies != nil && len(*bom.Dependencies) > 1)
		is.True(!digests[s.Digest]) // every SBOM has its own digest
		digests[s.Digest] = true
		if _, ok := versions[s.Artifact]; !ok {
			set := map[string]string{}
			for _, c := range *bom.Components {
				set[c.Name] = c.PackageURL
			}
			versions[s.Artifact] = set
		}
	}
	is.Equal(len(versions), 4)

	// Artifacts 0 and 2 share base image 0, so they share its OS packages.
	a0, a2 := versions["loadgen.test/golang-app-000"], versions["loadgen.test/pypi-app-002"]
	is.Equal(a0["openssl"], "pkg:apk/alpine/openssl@3.0.7-r0")
	is.Equal(a2["openssl"], a0["openssl"])
}

func TestGenerateChurn(t *testing.T) {
	is := is.New(t)
	spec := smallSpec
	spec.Artifacts, spec.Versions, spec.Components, spec.Churn = 1, 2, 1000, 0.05
	sboms := collect(t, spec)
	purls := func(s SBOM) map[string]bool {
		var bom cdx.BOM
		is.NoErr(json.Unmarshal(s.Doc, &bom))
		out := map[string]bool{}
		for _, c := range *bom.Components {
			out[c.PackageURL] = true
		}
		return out
	}
	first, second := purls(sboms[0]), purls(sboms[1])
	changed := 0
	for p := range second {
		if !first[p] {
			changed++
		}
	}
	is.True(changed > 20 && changed < 80) // about 5% of 1000
}
