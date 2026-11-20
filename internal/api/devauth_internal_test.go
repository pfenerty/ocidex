package api

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestDevPersonasMatchSeedScript keeps devPersonas equal to the PERSONAS array
// in scripts/dev-auth.sh, which stays the one place a persona is added.
func TestDevPersonasMatchSeedScript(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/dev-auth.sh")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)\nPERSONAS=\((.*?)\n\)`).FindSubmatch(raw)
	if block == nil {
		t.Fatal("no PERSONAS=( ... ) array in scripts/dev-auth.sh")
	}
	seeded := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([a-z0-9]+):`).FindAllSubmatch(block[1], -1) {
		seeded[string(m[1])] = true
	}
	if len(seeded) == 0 {
		t.Fatal("PERSONAS array parsed empty")
	}
	for name := range seeded {
		if !devPersonas[name] {
			t.Errorf("scripts/dev-auth.sh seeds %q but devPersonas does not allow it", name)
		}
	}
	for name := range devPersonas {
		if !seeded[name] {
			t.Errorf("devPersonas allows %q but scripts/dev-auth.sh does not seed it", strings.ToLower(name))
		}
	}
}
