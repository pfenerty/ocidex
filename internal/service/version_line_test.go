package service

import (
	"encoding/json"
	"os"
	"testing"
)

// versionLineCase is one row of the golden file shared with the web client and
// the sbom generated columns.
type versionLineCase struct {
	Version    string `json:"version"`
	Variant    string `json:"variant"`
	Prerelease bool   `json:"prerelease"`
}

// loadVersionLineGolden reads the cases every implementation of the rule is
// held to.
func loadVersionLineGolden(t *testing.T) []versionLineCase {
	t.Helper()
	raw, err := os.ReadFile("../../web/src/utils/versionLine.golden.json")
	if err != nil {
		t.Fatalf("reading golden file: %v", err)
	}
	var cases []versionLineCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("decoding golden file: %v", err)
	}
	return cases
}

func TestVersionLine_Golden(t *testing.T) {
	for _, c := range loadVersionLineGolden(t) {
		t.Run(c.Version, func(t *testing.T) {
			variant, prerelease := VersionLine(c.Version)
			if variant != c.Variant || prerelease != c.Prerelease {
				t.Fatalf("VersionLine(%q) = (%q, %v), want (%q, %v)",
					c.Version, variant, prerelease, c.Variant, c.Prerelease)
			}
		})
	}
}
