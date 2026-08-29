package repository

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ownerIDRef matches the bare token. It does not match owner_user_id (the
// CreateNamespace/CreateRegistry parameter, which names a user and not a
// namespace column) or namespace_owner(, because neither contains the token
// with word boundaries on both sides.
var ownerIDRef = regexp.MustCompile(`\bowner_id\b`)

// TestNoOwnerIDInQueries fails if owner_id reappears under db/queries/ as
// anything other than an output column name.
//
// namespace.owner_id is gone (ocidex-y0hg.4); ownership is a namespace_member
// row with role='owner'. The column's semantics are the thing that creeps back,
// not the column itself: the compiler cannot catch `JOIN namespace n ... WHERE
// n.owner_id = $1` being reintroduced as a hand-rolled ownership test, because
// after the migration it simply fails to compile — but it can be reintroduced
// as a join to namespace_member that filters on role='owner' and means the same
// wrong thing, quietly excluding the four other roles from a feed that should
// include them. A source scan is a blunt instrument and it is the one that
// catches this, the same way TestVisibilityFilterHasOneConstructor catches a
// fourth hand-rolled visibility filter.
//
// The one permitted form is `AS owner_id`, which names a value projected by
// namespace_owner() for a response body. Rendering an owner is fine; filtering
// on one is what owned_namespace_ids and namespace_ids_with_capability are for.
func TestNoOwnerIDInQueries(t *testing.T) {
	dir := filepath.Join("..", "..", "db", "queries")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		src, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		text := string(src)

		for _, loc := range ownerIDRef.FindAllStringIndex(text, -1) {
			if isProjectionAlias(text, loc[0]) {
				continue
			}
			t.Errorf("%s:%d: owner_id is not a column any more — ownership is a "+
				"namespace_member row with role='owner'.\n"+
				"To filter: owned_namespace_ids() or namespace_ids_with_capability(). "+
				"To render: namespace_owner(...) AS owner_id.",
				e.Name(), 1+strings.Count(text[:loc[0]], "\n"))
		}
	}
}

// isProjectionAlias reports whether the owner_id token at start is the target
// of an AS, i.e. the name of a projected column rather than a reference to one.
func isProjectionAlias(text string, start int) bool {
	before := strings.TrimRight(text[:start], " \t\n")
	return strings.HasSuffix(strings.ToUpper(before), " AS") ||
		strings.HasSuffix(strings.ToUpper(before), "\tAS")
}
