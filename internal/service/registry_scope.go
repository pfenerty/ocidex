package service

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Tag orders a registry's selection window can use (ADR-0053 S2). The empty
// string is "auto": semver when tag_patterns contains the semver keyword,
// created otherwise.
const (
	TagOrderSemver  = "semver"
	TagOrderCreated = "created"
	TagOrderLexical = "lexical"
)

// DefaultTagLimit is how many tags per repository a registry keeps when the
// caller does not say (ADR-0053 S1). 0 means unlimited.
const DefaultTagLimit = 50

// EffectiveTagOrder resolves the auto order: an explicit TagOrder wins, then
// semver when TagPatterns names it, then created.
func (r Registry) EffectiveTagOrder() string {
	if r.TagOrder != "" {
		return r.TagOrder
	}
	if slices.Contains(r.TagPatterns, "semver") {
		return TagOrderSemver
	}
	return TagOrderCreated
}

// ValidateScanScope checks a registry's window settings as a whole, so every
// caller (API, CLI through the API, operator) gets the same answer.
func ValidateScanScope(tagLimit int, tagOrder string, maxTagAgeDays int, tagPatterns []string) error {
	if tagLimit < 0 {
		return &ValidationError{Message: "tag_limit must be 0 (unlimited) or more"}
	}
	switch tagOrder {
	case "", TagOrderSemver, TagOrderCreated, TagOrderLexical:
	default:
		return &ValidationError{Message: fmt.Sprintf("tag_order must be semver, created or lexical, not %q", tagOrder)}
	}
	if maxTagAgeDays < 0 {
		return &ValidationError{Message: "max_tag_age_days must be 1 or more, or 0 for no age limit"}
	}
	order := Registry{TagOrder: tagOrder, TagPatterns: tagPatterns}.EffectiveTagOrder()
	if maxTagAgeDays > 0 && order != TagOrderCreated {
		return &ValidationError{Message: fmt.Sprintf("max_tag_age_days needs tag_order created; the effective order is %s", order)}
	}
	return nil
}

// WalkStats is what one catalog walk of a registry selected (ADR-0053 S7),
// summed over its repositories. Error is set when the walk could not list the
// registry at all; per-repository failures are logged and leave their counts out.
type WalkStats struct {
	At             time.Time `json:"at" doc:"When the walk finished"`
	Repositories   int       `json:"repositories" doc:"Repositories the walk visited"`
	Matched        int       `json:"matched" doc:"Tags that passed the filter"`
	Selected       int       `json:"selected" doc:"Tags inside the window"`
	SkippedByLimit int       `json:"skipped_by_limit" doc:"Matching tags past tag_limit"`
	SkippedByAge   int       `json:"skipped_by_age" doc:"Matching tags older than max_tag_age_days"`
	Queued         int       `json:"queued" doc:"Scan jobs the walk submitted (already-ingested digests are not)"`
	Error          string    `json:"error,omitempty" doc:"Why the walk failed, if it did"`
}

// TagWindow is the outcome of applying a registry's selection window to one
// repository's candidate tags.
type TagWindow struct {
	Selected       []string // newest first
	SkippedByAge   int
	SkippedByLimit int
}

// CreatedFunc returns the build date of a tag's (or an untagged digest's)
// image, and false when it has none or it cannot be read.
type CreatedFunc func(ref string) (time.Time, bool)

// SelectTags orders the candidate tags of one repository and keeps the newest
// TagLimit of them, after dropping those older than MaxTagAgeDays (ADR-0053
// S1, S2). Candidates have already passed the filter step. created is called
// only when the effective order is created, once per candidate.
func (r Registry) SelectTags(candidates []string, created CreatedFunc, now time.Time) TagWindow {
	return selectWindow(candidates, r.EffectiveTagOrder(), r.TagLimit, r.MaxTagAgeDays, created, now)
}

// SelectUntagged applies the same window to untagged digests, always ordered
// by created, since they have no names to compare (ADR-0053 S4).
func (r Registry) SelectUntagged(digests []string, created CreatedFunc, now time.Time) TagWindow {
	return selectWindow(digests, TagOrderCreated, r.TagLimit, r.MaxTagAgeDays, created, now)
}

func selectWindow(refs []string, order string, limit, maxAgeDays int, created CreatedFunc, now time.Time) TagWindow {
	var w TagWindow
	sorted := slices.Clone(refs)
	switch order {
	case TagOrderCreated:
		dates := make(map[string]time.Time, len(sorted))
		for _, ref := range sorted {
			if t, ok := created(ref); ok {
				dates[ref] = t
			}
		}
		if maxAgeDays > 0 {
			cutoff := now.AddDate(0, 0, -maxAgeDays)
			sorted = slices.DeleteFunc(sorted, func(ref string) bool {
				t, ok := dates[ref]
				return !ok || t.Before(cutoff)
			})
			w.SkippedByAge = len(refs) - len(sorted)
		}
		slices.SortFunc(sorted, func(a, b string) int { return newestFirst(compareCreated(a, b, dates), a, b) })
	case TagOrderSemver:
		slices.SortFunc(sorted, func(a, b string) int { return newestFirst(compareSemverTags(a, b), a, b) })
	default:
		slices.SortFunc(sorted, func(a, b string) int { return newestFirst(0, a, b) })
	}
	if limit > 0 && len(sorted) > limit {
		w.SkippedByLimit = len(sorted) - limit
		sorted = sorted[:limit]
	}
	w.Selected = sorted
	return w
}

// newestFirst turns an ascending comparison (positive when a is newer) into a
// sort key that puts the newest first, breaking ties by the raw string,
// byte-wise descending. Names are unique within a repository, so the order is
// total and the same input always selects the same window.
func newestFirst(cmp int, a, b string) int {
	if cmp != 0 {
		return -cmp
	}
	return -strings.Compare(a, b)
}

// compareCreated puts dated refs ahead of undated ones and later dates ahead of
// earlier ones.
func compareCreated(a, b string, dates map[string]time.Time) int {
	ta, okA := dates[a]
	tb, okB := dates[b]
	switch {
	case okA && okB:
		return ta.Compare(tb)
	case okA:
		return 1
	case okB:
		return -1
	}
	return 0
}

// compareSemverTags compares by SemVer 2.0.0 precedence, ignoring a leading v
// and build metadata. A tag semverRe does not parse is older than every tag it
// does.
func compareSemverTags(a, b string) int {
	ma, mb := semverRe.FindStringSubmatch(a), semverRe.FindStringSubmatch(b)
	switch {
	case ma == nil && mb == nil:
		return 0
	case ma == nil:
		return -1
	case mb == nil:
		return 1
	}
	for i := 1; i <= 3; i++ {
		if c := compareNumeric(ma[i], mb[i]); c != 0 {
			return c
		}
	}
	return comparePrerelease(strings.TrimPrefix(ma[4], "-"), strings.TrimPrefix(mb[4], "-"))
}

// comparePrerelease implements SemVer §11.3-4: a release is newer than any of
// its prereleases, and identifiers compare left to right.
func comparePrerelease(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, nb := isNumeric(pa[i]), isNumeric(pb[i])
		var c int
		switch {
		case na && nb:
			c = compareNumeric(pa[i], pb[i])
		case na:
			c = -1
		case nb:
			c = 1
		default:
			c = strings.Compare(pa[i], pb[i])
		}
		if c != 0 {
			return c
		}
	}
	return len(pa) - len(pb)
}

// compareNumeric compares two digit strings as integers of any size, so leading
// zeros and values past int64 compare correctly.
func compareNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return strings.Compare(a, b)
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
