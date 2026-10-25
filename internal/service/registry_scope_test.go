package service

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

var scopeNow = time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)

func noDates(string) (time.Time, bool) { return time.Time{}, false }

func datesFrom(m map[string]time.Time) CreatedFunc {
	return func(ref string) (time.Time, bool) {
		t, ok := m[ref]
		return t, ok
	}
}

func TestSelectTagsSemverOrder(t *testing.T) {
	is := is.New(t)
	// ADR-0053 S2's worked example, shuffled.
	tags := []string{
		"latest", "v1.9.3-alpha", "1.9.3", "v1.9.2", "v1.9.3-rc.2", "stable", "v1.10.0",
		"v1.9.3-beta", "v1.9.3", "v1.9.3-alpha.1", "v1.9.3-rc.10",
	}
	reg := Registry{TagPatterns: []string{"semver", "latest", "stable"}}
	w := reg.SelectTags(tags, noDates, scopeNow)
	is.Equal(w.Selected, []string{
		"v1.10.0", "v1.9.3", "1.9.3", "v1.9.3-rc.10", "v1.9.3-rc.2", "v1.9.3-beta",
		"v1.9.3-alpha.1", "v1.9.3-alpha", "v1.9.2", "stable", "latest",
	})
	is.Equal(w.SkippedByLimit, 0) // TagLimit 0 is unlimited
}

func TestSelectTagsSemverDetails(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		want []string
	}{
		{"integers not strings", []string{"1.9.0", "1.10.0", "1.2.0"}, []string{"1.10.0", "1.9.0", "1.2.0"}},
		{"leading zeros are integers", []string{"01.2.3", "1.2.4", "1.02.3"}, []string{"1.2.4", "1.02.3", "01.2.3"}},
		{"build metadata ties, string breaks it", []string{"1.0.0+b.1", "1.0.0+b.2"}, []string{"1.0.0+b.2", "1.0.0+b.1"}},
		{"numeric prerelease older than alphanumeric", []string{"1.0.0-alpha", "1.0.0-1"}, []string{"1.0.0-alpha", "1.0.0-1"}},
		{"huge numbers", []string{"99999999999999999999.0.0", "1.0.0"}, []string{"99999999999999999999.0.0", "1.0.0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			w := Registry{TagPatterns: []string{"semver"}}.SelectTags(tc.tags, noDates, scopeNow)
			is.Equal(w.Selected, tc.want)
		})
	}
}

func TestSelectTagsLimit(t *testing.T) {
	is := is.New(t)
	reg := Registry{TagPatterns: []string{"semver", "latest"}, TagLimit: 2}
	w := reg.SelectTags([]string{"latest", "1.0.0", "1.1.0", "1.2.0"}, noDates, scopeNow)
	is.Equal(w.Selected, []string{"1.2.0", "1.1.0"})
	is.Equal(w.SkippedByLimit, 2) // latest is unparseable, so it sorts out of the window
}

func TestSelectTagsLexical(t *testing.T) {
	is := is.New(t)
	reg := Registry{TagOrder: TagOrderLexical, TagLimit: 3}
	w := reg.SelectTags([]string{"20261019", "20261020", "9", "10", "20250101"}, noDates, scopeNow)
	is.Equal(w.Selected, []string{"9", "20261020", "20261019"})
	is.Equal(w.SkippedByLimit, 2)
}

func TestSelectTagsCreated(t *testing.T) {
	is := is.New(t)
	day := func(d int) time.Time { return scopeNow.AddDate(0, 0, -d) }
	dates := datesFrom(map[string]time.Time{
		"a": day(1), "b": day(5), "c": day(5), "d": day(40),
	})
	// No tag_patterns, no tag_order: auto resolves to created. "nodate" sorts last.
	w := Registry{}.SelectTags([]string{"d", "nodate", "b", "a", "c"}, dates, scopeNow)
	is.Equal(w.Selected, []string{"a", "c", "b", "d", "nodate"})

	t.Run("max age drops old and undated", func(t *testing.T) {
		is := is.New(t)
		w := Registry{MaxTagAgeDays: 30, TagLimit: 2}.SelectTags([]string{"d", "nodate", "b", "a", "c"}, dates, scopeNow)
		is.Equal(w.Selected, []string{"a", "c"})
		is.Equal(w.SkippedByAge, 2)
		is.Equal(w.SkippedByLimit, 1)
	})
}

func TestSelectTagsOnlyAsksDatesUnderCreated(t *testing.T) {
	is := is.New(t)
	called := false
	created := func(string) (time.Time, bool) { called = true; return time.Time{}, false }
	Registry{TagPatterns: []string{"semver"}}.SelectTags([]string{"1.0.0"}, created, scopeNow)
	Registry{TagOrder: TagOrderLexical}.SelectTags([]string{"a"}, created, scopeNow)
	is.True(!called)
}

func TestSelectUntaggedIgnoresTagOrder(t *testing.T) {
	is := is.New(t)
	dates := datesFrom(map[string]time.Time{"sha256:old": scopeNow.AddDate(0, 0, -9), "sha256:new": scopeNow})
	reg := Registry{TagOrder: TagOrderLexical, TagLimit: 1}
	w := reg.SelectUntagged([]string{"sha256:old", "sha256:new"}, dates, scopeNow)
	is.Equal(w.Selected, []string{"sha256:new"})
	is.Equal(w.SkippedByLimit, 1)
}

func TestValidateScanScope(t *testing.T) {
	cases := []struct {
		name     string
		limit    int
		order    string
		maxAge   int
		patterns []string
		ok       bool
	}{
		{"defaults", DefaultTagLimit, "", 0, nil, true},
		{"unlimited", 0, "", 0, nil, true},
		{"negative limit", -1, "", 0, nil, false},
		{"unknown order", 50, "newest", 0, nil, false},
		{"age with auto created", 50, "", 30, nil, true},
		{"age with auto semver", 50, "", 30, []string{"semver"}, false},
		{"age with explicit created over semver patterns", 50, TagOrderCreated, 30, []string{"semver"}, true},
		{"age with lexical", 50, TagOrderLexical, 30, nil, false},
		{"negative age", 50, "", -1, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			err := ValidateScanScope(tc.limit, tc.order, tc.maxAge, tc.patterns)
			if tc.ok {
				is.NoErr(err)
				return
			}
			var ve *ValidationError
			is.True(errors.As(err, &ve))
		})
	}
}

func TestLastWalkRoundTrip(t *testing.T) {
	is := is.New(t)
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	b, err := json.Marshal(WalkStats{At: at, Repositories: 2, Matched: 30, Selected: 10, SkippedByLimit: 20, Queued: 4})
	is.NoErr(err)
	r := fromRepo(registryComposite{reg: repository.Registry{LastWalkStats: b}})
	is.True(r.LastWalk != nil)
	is.Equal(r.LastWalk.Selected, 10)
	is.Equal(r.LastWalk.At, at)

	is.True(fromRepo(registryComposite{}).LastWalk == nil) // never walked
}

// Walk stats stored before the camelCase rename still read back (ocidex-nps9.32).
func TestWalkStatsReadsLegacyKeys(t *testing.T) {
	is := is.New(t)
	var w WalkStats
	is.NoErr(json.Unmarshal([]byte(`{"at":"2026-10-20T12:00:00Z","selected":10,"skipped_by_limit":20,"skipped_by_age":3,"queued":4}`), &w))
	is.Equal(w.Selected, 10)
	is.Equal(w.SkippedByLimit, 20)
	is.Equal(w.SkippedByAge, 3)

	b, err := json.Marshal(w)
	is.NoErr(err)
	is.True(strings.Contains(string(b), `"skippedByLimit":20`))
}
