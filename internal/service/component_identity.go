// The component identity model of ADR-0019: how a purl and a (type, name,
// group) tuple collapse into the key two SBOMs are joined on, and the
// versioned-name post-pass that reconciles what that key cannot. Split out
// of changelog.go — this is the contract diff correctness rests on.

package service

import (
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// versionSuffixRe matches a trailing version suffix in a package name,
// e.g. "-1.25" in "go-1.25" or "-3.12" in "python-3.12".
var versionSuffixRe = regexp.MustCompile(`-[0-9][0-9.]*$`)

// distroVersionSuffixRe matches a trailing version suffix on a distro
// qualifier value, e.g. "-3.14.3" in "alpine-3.14.3" or "-34" in "fedora-34".
// Used to normalize distro to family-only for identity (ADR-0019 Rule 1).
var distroVersionSuffixRe = regexp.MustCompile(`-[0-9][A-Za-z0-9.-]*$`)

// identityQualifiers are the only purl qualifiers that contribute to component identity.
// Everything else is noise (download_url, checksum, tag, commit, vcs_url, …).
var identityQualifiers = map[string]bool{
	"distro":         true,
	"arch":           true,
	"epoch":          true,
	"repository_url": true,
}

func buildPackageMap(rows []repository.ListSBOMPackagesRow) map[string]componentIdentity {
	m := make(map[string]componentIdentity, len(rows))
	for _, row := range rows {
		key := componentKey(row.Type, row.Name, row.GroupName, row.Purl)
		m[key] = componentIdentity{
			version: textToPtr(row.Version),
			purl:    textToPtr(row.Purl),
			name:    row.Name,
			group:   textToPtr(row.GroupName),
		}
	}
	return m
}

// componentIdentity holds the fields used to match a component across SBOMs.
//
// name and group are carried alongside the matching fields purely so the diff
// can report them. They are not part of the identity — the map key already is —
// but without them the only source of a display name is the key itself, and
// deriving one from a purl key loses information: nameFromKey takes the last
// path segment, which turns "pkg:golang/github.com/sigstore/cosign/v2" into
// "v2". The real name was read from the database and then thrown away.
type componentIdentity struct {
	version *string
	purl    *string
	name    string
	group   *string
}

// displayName returns the component's recorded name, falling back to deriving
// one from the map key for identities built before the name was carried (or by
// a caller that has none).
func (c componentIdentity) displayName(key string) string {
	if c.name != "" {
		return c.name
	}
	return nameFromKey(key)
}

// displayGroup mirrors displayName. The recorded group is authoritative even
// when it is nil, so the key-derived fallback applies only when the whole
// identity lacks a name.
func (c componentIdentity) displayGroup(key string) *string {
	if c.name != "" {
		return c.group
	}
	return groupFromKey(key)
}

// buildComponentMap creates a map of component identity key → component info.
func buildComponentMap(rows []repository.ListSBOMComponentsRow) map[string]componentIdentity {
	m := make(map[string]componentIdentity, len(rows))
	for _, row := range rows {
		key := componentKey(row.Type, row.Name, row.GroupName, row.Purl)
		m[key] = componentIdentity{
			version: textToPtr(row.Version),
			purl:    textToPtr(row.Purl),
			name:    row.Name,
			group:   textToPtr(row.GroupName),
		}
	}
	return m
}

// componentKey generates the identity key for matching across SBOMs.
// Uses purl (without version) if available, otherwise (type, name, group).
func componentKey(typ, name string, group, purl pgtype.Text) string {
	if purl.Valid && purl.String != "" {
		return normalizeComponentPurl(purl.String)
	}
	g := ""
	if group.Valid {
		g = group.String
	}
	return typ + "\x00" + name + "\x00" + g
}

// stripPurlVersion removes the version component from a purl.
// e.g. "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.15" → "pkg:deb/ubuntu/curl"
func stripPurlVersion(purl string) string {
	if idx := strings.Index(purl, "@"); idx != -1 {
		return purl[:idx]
	}
	return purl
}

// normalizeComponentPurl strips the version segment and filters qualifiers to
// only those in identityQualifiers, sorted alphabetically. Implements ADR 0019 Rule 1.
// Purl format: pkg:type/namespace/name@version?qualifiers — qualifiers follow the version.
func normalizeComponentPurl(purl string) string {
	// Split qualifiers first — they come after version in purl format.
	path, qs, hasQ := strings.Cut(purl, "?")
	// Strip version from path (everything after @).
	if idx := strings.Index(path, "@"); idx != -1 {
		path = path[:idx]
	}
	if !hasQ || qs == "" {
		return path
	}
	var kept []string
	for _, kv := range strings.Split(qs, "&") {
		k, val, _ := strings.Cut(kv, "=")
		if !identityQualifiers[k] {
			continue
		}
		if k == "distro" {
			val = distroVersionSuffixRe.ReplaceAllString(val, "")
			kept = append(kept, k+"="+val)
			continue
		}
		kept = append(kept, kv)
	}
	if len(kept) == 0 {
		return path
	}
	sort.Strings(kept)
	return path + "?" + strings.Join(kept, "&")
}

// diffComponents computes the diff between two component maps.
func diffComponents(from, to SBOMRef, oldMap, newMap map[string]componentIdentity) ChangelogEntry {
	entry := ChangelogEntry{
		From:    from,
		To:      to,
		Changes: []ComponentDiff{},
	}

	// First pass: exact key matching.
	for key, curr := range newMap {
		prev, exists := oldMap[key]
		if !exists {
			entry.Changes = append(entry.Changes, ComponentDiff{
				Type:    dirAdded,
				Name:    curr.displayName(key),
				Group:   curr.displayGroup(key),
				Version: curr.version,
				Purl:    curr.purl,
			})
		} else if !versionsEqual(prev.version, curr.version) {
			entry.Changes = append(entry.Changes, ComponentDiff{
				Type:            dirModified,
				Name:            curr.displayName(key),
				Group:           curr.displayGroup(key),
				Version:         curr.version,
				Purl:            curr.purl,
				PreviousVersion: prev.version,
			})
		}
	}
	for key, prev := range oldMap {
		if _, exists := newMap[key]; !exists {
			entry.Changes = append(entry.Changes, ComponentDiff{
				Type:    dirRemoved,
				Name:    prev.displayName(key),
				Group:   prev.displayGroup(key),
				Version: prev.version,
				Purl:    prev.purl,
			})
		}
	}

	// Second pass: reconcile version-named package replacements.
	// e.g. "go-1.24 removed + go-1.25 added" → "go-1.25 upgraded from 1.24.x".
	newNormCount := make(map[string]int, len(newMap))
	for key := range newMap {
		if nk := normKeyFromComponentKey(key); nk != "" {
			newNormCount[nk]++
		}
	}
	entry.Changes = reconcileVersionedPackages(entry.Changes, newNormCount)

	// Populate Direction and compute summary from final change list.
	for i := range entry.Changes {
		entry.Changes[i].Direction = classifyDirection(entry.Changes[i])
		addSummaryCount(&entry.Summary, entry.Changes[i].Direction)
	}

	// Sort: removed, modified, added, then by name.
	typeOrder := map[string]int{dirRemoved: 0, dirModified: 1, dirAdded: 2}
	sort.Slice(entry.Changes, func(i, j int) bool {
		if typeOrder[entry.Changes[i].Type] != typeOrder[entry.Changes[j].Type] {
			return typeOrder[entry.Changes[i].Type] < typeOrder[entry.Changes[j].Type]
		}
		return entry.Changes[i].Name < entry.Changes[j].Name
	})

	return entry
}

// versionedNormKey returns a normalized key for a ComponentDiff to detect version-suffix replacements
// (e.g. "go-1.24" and "go-1.25" share the key "go"). Returns "" when no suffix is present.
func versionedNormKey(c ComponentDiff) string {
	if c.Purl != nil {
		stripped := stripPurlVersion(*c.Purl)
		idx := strings.LastIndex(stripped, "/")
		if idx < 0 {
			return ""
		}
		name := stripped[idx+1:]
		if q := strings.Index(name, "?"); q >= 0 {
			name = name[:q]
		}
		normalized := versionSuffixRe.ReplaceAllString(name, "")
		if normalized == name {
			return ""
		}
		return stripped[:idx+1] + normalized
	}
	normalized := versionSuffixRe.ReplaceAllString(c.Name, "")
	if normalized == c.Name {
		return ""
	}
	return normalized
}

// reconcileVersionedPackages re-matches removed+added pairs whose package names
// share a base but differ only by a trailing version suffix (e.g. go-1.24 / go-1.25).
// Matched pairs are collapsed into a single "modified" entry so classifyChange
// can determine upgraded vs downgraded from the version numbers.
func reconcileVersionedPackages(changes []ComponentDiff, newNormCount map[string]int) []ComponentDiff {
	type candidate struct {
		idx  int
		diff ComponentDiff
	}

	removedByNorm := map[string]candidate{}
	addedByNorm := map[string]candidate{}

	for i, c := range changes {
		nk := versionedNormKey(c)
		if nk == "" {
			continue
		}
		switch c.Type {
		case dirRemoved:
			if _, exists := removedByNorm[nk]; !exists {
				removedByNorm[nk] = candidate{i, c}
			}
		case dirAdded:
			if _, exists := addedByNorm[nk]; !exists {
				addedByNorm[nk] = candidate{i, c}
			}
		}
	}

	toRemove := map[int]bool{}
	var extra []ComponentDiff

	for nk, added := range addedByNorm {
		removed, ok := removedByNorm[nk]
		if !ok || added.diff.Name == removed.diff.Name {
			continue
		}
		// Survivor guard: if >1 new component shares this normalized base, collapsing
		// would be misleading (another version survived alongside the upgrade/downgrade).
		if newNormCount[nk] > 1 {
			continue
		}
		extra = append(extra, ComponentDiff{
			Type:            dirModified,
			Name:            added.diff.Name,
			Group:           added.diff.Group,
			Version:         added.diff.Version,
			Purl:            added.diff.Purl,
			PreviousVersion: removed.diff.Version,
		})
		toRemove[added.idx] = true
		toRemove[removed.idx] = true
	}

	if len(extra) == 0 {
		return changes
	}

	result := make([]ComponentDiff, 0, len(changes)-len(toRemove)+len(extra))
	for i, c := range changes {
		if !toRemove[i] {
			result = append(result, c)
		}
	}
	return append(result, extra...)
}

// nameFromKey extracts the name from a component key.
// For purl keys, extracts the package name from the purl.
// For tuple keys (type\x00name\x00group), returns the name part.
func nameFromKey(key string) string {
	if strings.HasPrefix(key, "pkg:") {
		name := key
		if idx := strings.LastIndex(name, "/"); idx != -1 {
			name = name[idx+1:]
		}
		if idx := strings.Index(name, "?"); idx != -1 {
			name = name[:idx]
		}
		return name
	}
	parts := strings.SplitN(key, "\x00", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	return key
}

// normKeyFromComponentKey returns the normalized versioned-name base for a component
// identity key (purl or tuple form). Returns "" when no version suffix is present.
// Used by the survivor guard in reconcileVersionedPackages.
func normKeyFromComponentKey(key string) string {
	if strings.HasPrefix(key, "pkg:") {
		idx := strings.LastIndex(key, "/")
		if idx < 0 {
			return ""
		}
		name := key[idx+1:]
		if q := strings.Index(name, "?"); q >= 0 {
			name = name[:q]
		}
		normalized := versionSuffixRe.ReplaceAllString(name, "")
		if normalized == name {
			return ""
		}
		return key[:idx+1] + normalized
	}
	// Tuple form: "type\x00name\x00group" — normalize only the name to match versionedNormKey.
	parts := strings.SplitN(key, "\x00", 3)
	if len(parts) != 3 {
		return ""
	}
	normalized := versionSuffixRe.ReplaceAllString(parts[1], "")
	if normalized == parts[1] {
		return ""
	}
	return normalized
}

// groupFromKey extracts the group from a component key, if present.
func groupFromKey(key string) *string {
	if strings.HasPrefix(key, "pkg:") {
		return nil
	}
	parts := strings.SplitN(key, "\x00", 3)
	if len(parts) >= 3 && parts[2] != "" {
		return &parts[2]
	}
	return nil
}
