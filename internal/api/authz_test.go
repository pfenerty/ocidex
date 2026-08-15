package api_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVisibilityFilterHasOneConstructor guards the invariant that authz.go is
// the only place in the API layer that builds a service.VisibilityFilter. The
// filter is the row-level half of the authorization model, and it was
// hand-rolled in three handlers before ocidex-wp9b.3 — each copy free to drift
// on IsAdmin or on what an unauthenticated caller sees. A source scan is a
// blunt instrument, but it is the only thing that catches a fourth copy being
// written, because a wrong-but-consistent copy passes every behavioural test
// that only exercises the caller it was written for.
func TestVisibilityFilterHasOneConstructor(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir: %v", err)
	}

	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || name == "authz.go" {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if strings.Contains(string(src), "service.VisibilityFilter{") {
			offenders = append(offenders, name)
		}
	}

	if len(offenders) > 0 {
		t.Errorf("service.VisibilityFilter is constructed outside authz.go in: %s\n"+
			"use visibilityFilterFromContext(ctx) instead", strings.Join(offenders, ", "))
	}
}
