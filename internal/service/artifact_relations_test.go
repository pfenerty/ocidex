package service

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

// ADR-048's two rules, at the level where they are decided.
//
// The integration tests prove the rules produce the right relationships; these
// prove the predicate itself, including the cases a fixture cannot conveniently
// reach — a component purl that is not Go, a single-segment module, a path with
// no basename.

func text(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }

func TestModulePurlBasesWalksPathBoundaries(t *testing.T) {
	is := is.New(t)

	// Every proper prefix of the module path, so the coarse SQL branch can find
	// a module component from a command artifact without knowing where the
	// module path ends — pkg:golang/github.com/pfenerty/ocidex is in here, and
	// so is the shorter github.com/pfenerty in case a module is that short.
	is.Equal(
		modulePurlBases(text("pkg:golang/github.com/pfenerty/ocidex/cmd/git-worker")),
		[]string{
			"pkg:golang/github.com",
			"pkg:golang/github.com/pfenerty",
			"pkg:golang/github.com/pfenerty/ocidex",
			"pkg:golang/github.com/pfenerty/ocidex/cmd",
		})

	// Not a Go purl: R6 is scoped to pkg:golang, so there is nothing to widen.
	is.Equal(modulePurlBases(text("pkg:npm/@scope/thing")), nil)

	// A single path segment has no proper prefix to offer.
	is.Equal(modulePurlBases(text("pkg:golang/ocidex")), nil)

	// An absent purl asks nothing of the query.
	is.Equal(modulePurlBases(pgtype.Text{}), nil)
}

func TestCommandMatchRequiresAllFourConditions(t *testing.T) {
	is := is.New(t)

	const artifactPurl = "pkg:golang/github.com/pfenerty/ocidex/cmd/git-worker"
	const componentPurl = "pkg:golang/github.com/pfenerty/ocidex@v0.0.2"

	// The case the rule exists for: the module component's binary is this
	// command.
	is.True(commandMatch(text(artifactPurl), "git-worker", text(componentPurl), text("/git-worker")))

	// The same component in an image that ships a different command. This is
	// the assertion that separates R6 from a plain module match, which would
	// have said yes to all twelve of the module's commands.
	is.True(!commandMatch(text("pkg:golang/github.com/pfenerty/ocidex/cmd/vuln-worker"),
		"vuln-worker", text(componentPurl), text("/git-worker")))

	// R7: no recorded path is not a wildcard. Both the NULL and the empty
	// string arrive from the database this way.
	is.True(!commandMatch(text(artifactPurl), "git-worker", text(componentPurl), pgtype.Text{}))
	is.True(!commandMatch(text(artifactPurl), "git-worker", text(componentPurl), text("")))

	// A path boundary, not a string prefix: the component's module must end
	// where the artifact's path continues.
	is.True(!commandMatch(text("pkg:golang/github.com/pfenerty/ocidex-extra/cmd/git-worker"),
		"git-worker", text(componentPurl), text("/git-worker")))

	// Equal purls are not a command match — that is R1's job, and letting it
	// through here would make a module artifact contain itself.
	is.True(!commandMatch(text(componentPurl), "ocidex", text(componentPurl), text("/ocidex")))

	// Both sides must be Go. A generic component that happens to sit under the
	// same path says nothing about Go commands.
	is.True(!commandMatch(text(artifactPurl), "git-worker",
		text("pkg:generic/github.com/pfenerty/ocidex"), text("/git-worker")))
	is.True(!commandMatch(text("pkg:generic/github.com/pfenerty/ocidex/cmd/git-worker"),
		"git-worker", text(componentPurl), text("/git-worker")))

	// A missing purl on either side leaves nothing to compare.
	is.True(!commandMatch(pgtype.Text{}, "git-worker", text(componentPurl), text("/git-worker")))
	is.True(!commandMatch(text(artifactPurl), "git-worker", pgtype.Text{}, text("/git-worker")))

	// The path's basename is what counts, wherever in the image it sits.
	is.True(commandMatch(text(artifactPurl), "git-worker", text(componentPurl), text("/usr/local/bin/git-worker")))

	// Qualifiers on either purl are cut before the comparison, the same way
	// componentKey cuts them.
	is.True(commandMatch(text(artifactPurl+"?type=binary"), "git-worker",
		text(componentPurl+"?type=module"), text("/git-worker")))
}

// A container records the module as main-<sha> and the application SBOM as
// 0.0.0-<sha>; the same commit must not read as outdated (ocidex-nps9.4).
func TestSameVersionMatchesCommitSpellings(t *testing.T) {
	str := func(s string) *string { return &s }
	tests := []struct {
		name             string
		matched, current string
		want             bool
	}{
		{"identical", "v1.2.3", "v1.2.3", true},
		{"branch tag vs zero version", "main-bf2bab70", "0.0.0-bf2bab70", true},
		{"short vs pseudo-version", "main-bf2bab70", "v0.0.0-20251002000000-bf2bab70c1d2", true},
		{"different commits", "main-bf2bab70", "0.0.0-c1f24c0b", false},
		{"semver differs", "v1.2.1", "v1.2.3", false},
		{"date suffix is not a commit", "1.2-20240101", "1.3-20240101", false},
		{"too short to be a commit", "1.0-abc", "2.0-abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			got := sameVersion(str(tt.matched), str(tt.current))
			is.True(got != nil)
			is.Equal(*got, tt.want)
		})
	}
	is.New(t).True(sameVersion(nil, str("v1")) == nil)
}
