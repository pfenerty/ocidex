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
	offenders := scanPackageSources(t, "service.VisibilityFilter{")

	if len(offenders) > 0 {
		t.Errorf("service.VisibilityFilter is constructed outside authz.go in: %s\n"+
			"use visibilityFilterFromContext(ctx) instead", strings.Join(offenders, ", "))
	}
}

// TestCapabilityHasOneConstructor is the same guard for the operation-level
// half of the model: can() in authz.go is the only place in the API layer that
// calls authz.Allow.
//
// Allow carries two installation-wide rules that no call site should be free to
// re-decide — an admin short-circuits every capability, and a global viewer is
// capped at reading whatever role a namespace gave them. A second call site
// that reached for user.Grants directly, or passed its own idea of `present`,
// would drop one of those and still pass every behavioural test written for the
// caller it was added for. That is what ocidex-y0hg.5 replaced: three ownership
// middlewares that each re-derived the admin override.
func TestCapabilityHasOneConstructor(t *testing.T) {
	offenders := scanPackageSources(t, "authz.Allow(")

	if len(offenders) > 0 {
		t.Errorf("authz.Allow is called outside authz.go in: %s\n"+
			"use can(user, namespaceID, cap) or canFromContext(ctx, namespaceID, cap) instead",
			strings.Join(offenders, ", "))
	}
}

// scanPackageSources returns every non-test .go file in this package, other
// than authz.go itself, whose source contains needle. A source scan is a blunt
// instrument, but it is the only thing that catches a second copy being
// written: a wrong-but-consistent copy passes every behavioural test that only
// exercises the caller it was written for.
func scanPackageSources(t *testing.T, needle string) []string {
	t.Helper()

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
		if strings.Contains(string(src), needle) {
			offenders = append(offenders, name)
		}
	}
	return offenders
}
