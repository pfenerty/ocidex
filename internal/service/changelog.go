package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Changelog represents the full changelog for an artifact.
type Changelog struct {
	ArtifactID             string           `json:"artifactId"`
	AvailableArchitectures []string         `json:"availableArchitectures"`
	Entries                []ChangelogEntry `json:"entries"`
}

// ChangelogEntry represents a diff between two consecutive SBOMs.
type ChangelogEntry struct {
	From    SBOMRef         `json:"from"`
	To      SBOMRef         `json:"to"`
	Summary ChangeSummary   `json:"summary"`
	Changes []ComponentDiff `json:"changes"`
}

// SBOMRef is a lightweight reference to an SBOM in a changelog entry.
type SBOMRef struct {
	ID             string     `json:"id"`
	SubjectVersion *string    `json:"subjectVersion,omitempty"`
	Architecture   *string    `json:"architecture,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	BuildDate      *time.Time `json:"buildDate,omitempty"`
}

// ChangeSummary counts the number of changes by type.
type ChangeSummary struct {
	Added    int `json:"added"`
	Removed  int `json:"removed"`
	Modified int `json:"modified"`
}

// ComponentDiff represents a single component change between two SBOMs.
type ComponentDiff struct {
	Type            string  `json:"type"` // "added", "removed", "modified"
	Name            string  `json:"name"`
	Group           *string `json:"group,omitempty"`
	Version         *string `json:"version,omitempty"`
	Purl            *string `json:"purl,omitempty"`
	PreviousVersion *string `json:"previousVersion,omitempty"`
}

// DiffSBOMs computes the diff between two arbitrary SBOMs.
func (s *searchService) DiffSBOMs(ctx context.Context, fromID, toID pgtype.UUID, vis VisibilityFilter) (ChangelogEntry, error) {
	q := repository.New(s.db)

	// Access check for both SBOMs.
	for _, id := range []pgtype.UUID{fromID, toID} {
		visible, err := q.IsSBOMVisible(ctx, repository.IsSBOMVisibleParams{
			ID:      id,
			UserID:  vis.UserID,
			IsAdmin: visAdminBool(vis),
		})
		if err != nil {
			return ChangelogEntry{}, fmt.Errorf("checking sbom visibility: %w", err)
		}
		if !visible {
			return ChangelogEntry{}, ErrNotFound
		}
	}

	// Load "from" SBOM metadata.
	fromSBOM, err := q.GetSBOM(ctx, fromID)
	if err != nil {
		return ChangelogEntry{}, fmt.Errorf("getting from sbom: %w", err)
	}

	// Load "to" SBOM metadata.
	toSBOM, err := q.GetSBOM(ctx, toID)
	if err != nil {
		return ChangelogEntry{}, fmt.Errorf("getting to sbom: %w", err)
	}

	// Load components for both.
	fromComps, err := q.ListSBOMComponents(ctx, fromID)
	if err != nil {
		return ChangelogEntry{}, fmt.Errorf("listing from components: %w", err)
	}

	toComps, err := q.ListSBOMComponents(ctx, toID)
	if err != nil {
		return ChangelogEntry{}, fmt.Errorf("listing to components: %w", err)
	}

	fromRef := SBOMRef{
		ID:             uuidToString(fromSBOM.ID),
		SubjectVersion: textToPtr(fromSBOM.SubjectVersion),
		CreatedAt:      fromSBOM.CreatedAt.Time,
	}
	toRef := SBOMRef{
		ID:             uuidToString(toSBOM.ID),
		SubjectVersion: textToPtr(toSBOM.SubjectVersion),
		CreatedAt:      toSBOM.CreatedAt.Time,
	}

	return diffComponents(fromRef, toRef, buildComponentMap(fromComps), buildComponentMap(toComps)), nil
}

// changelogGroupKey identifies a unique (version, arch) pair for deduplication.
type changelogGroupKey struct{ version, arch string }

// changelogCandidate is a deduplicated SBOM representative for changelog diffing.
type changelogCandidate struct {
	sbom      repository.ListSBOMsByArtifactRow
	buildDate *time.Time
	arch      string
}

// GetArtifactChangelog generates a changelog by diffing consecutive SBOMs for an artifact.
// SBOMs are grouped by architecture, deduplicated by (version, arch), then diffed within
// the selected architecture's timeline.
func (s *searchService) GetArtifactChangelog(ctx context.Context, artifactID pgtype.UUID, subjectVersion, arch string, vis VisibilityFilter) (Changelog, error) {
	q := repository.New(s.db)

	// Access check.
	visible, err := q.IsArtifactVisible(ctx, repository.IsArtifactVisibleParams{
		AID:     artifactID,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		return Changelog{}, fmt.Errorf("checking artifact visibility: %w", err)
	}
	if !visible {
		return Changelog{}, ErrNotFound
	}

	sboms, err := q.ListSBOMsByArtifact(ctx, repository.ListSBOMsByArtifactParams{
		ArtifactID:     artifactID,
		SubjectVersion: textOrNull(subjectVersion),
		UserID:         vis.UserID,
		IsAdmin:        visAdminBool(vis),
		RowLimit:       10000,
		RowOffset:      0,
	})
	if err != nil {
		return Changelog{}, fmt.Errorf("listing sboms: %w", err)
	}

	meta := buildEnrichmentMetaMap(ctx, q, artifactID)
	best, available := deduplicateSBOMs(sboms, meta)
	selectedArch := selectArch(arch, available)
	candidates := filterByArch(best, selectedArch)
	sortCandidates(candidates)

	arches := make([]string, 0, len(available))
	for a := range available {
		arches = append(arches, a)
	}
	sort.Strings(arches)
	changelog := Changelog{
		ArtifactID:             uuidToString(artifactID),
		AvailableArchitectures: arches,
		Entries:                []ChangelogEntry{},
	}

	if len(candidates) < 2 {
		return changelog, nil
	}

	prevComps, err := q.ListSBOMComponents(ctx, candidates[0].sbom.ID)
	if err != nil {
		return Changelog{}, fmt.Errorf("listing components for sbom %s: %w", uuidToString(candidates[0].sbom.ID), err)
	}
	prevMap := buildComponentMap(prevComps)

	for i := 1; i < len(candidates); i++ {
		currComps, err := q.ListSBOMComponents(ctx, candidates[i].sbom.ID)
		if err != nil {
			return Changelog{}, fmt.Errorf("listing components for sbom %s: %w", uuidToString(candidates[i].sbom.ID), err)
		}
		currMap := buildComponentMap(currComps)

		fromRef := sbomToRef(candidates[i-1].sbom)
		fromRef.BuildDate = candidates[i-1].buildDate
		fromRef.Architecture = nonEmptyStrPtr(candidates[i-1].arch)
		toRef := sbomToRef(candidates[i].sbom)
		toRef.BuildDate = candidates[i].buildDate
		toRef.Architecture = nonEmptyStrPtr(candidates[i].arch)

		entry := diffComponents(fromRef, toRef, prevMap, currMap)
		if len(entry.Changes) > 0 {
			changelog.Entries = append(changelog.Entries, entry)
		}

		prevMap = currMap
	}

	// Reverse entries so newest diff is first.
	for i, j := 0, len(changelog.Entries)-1; i < j; i, j = i+1, j-1 {
		changelog.Entries[i], changelog.Entries[j] = changelog.Entries[j], changelog.Entries[i]
	}

	return changelog, nil
}

// deduplicateSBOMs groups SBOMs by (version, arch) keeping the latest per group.
// Returns the best-per-group map and the set of available architectures.
func deduplicateSBOMs(sboms []repository.ListSBOMsByArtifactRow, meta map[pgtype.UUID]enrichmentMeta) (map[changelogGroupKey]changelogCandidate, map[string]bool) {
	best := map[changelogGroupKey]changelogCandidate{}
	available := map[string]bool{}
	for _, sbom := range sboms {
		m := meta[sbom.ID]
		sv := sbom.SubjectVersion.String
		if !sbom.SubjectVersion.Valid || sv == "" {
			sv = uuidToString(sbom.ID)
		}
		key := changelogGroupKey{sv, m.architecture}
		prev, exists := best[key]
		if !exists || laterThan(m.buildDate, sbom.CreatedAt.Time, prev.buildDate, prev.sbom.CreatedAt.Time) {
			best[key] = changelogCandidate{sbom: sbom, buildDate: m.buildDate, arch: m.architecture}
		}
		available[m.architecture] = true
	}
	return best, available
}

// filterByArch returns candidates matching the given architecture.
func filterByArch(best map[changelogGroupKey]changelogCandidate, arch string) []changelogCandidate {
	var out []changelogCandidate
	for k, c := range best {
		if k.arch == arch {
			out = append(out, c)
		}
	}
	return out
}

// sortCandidates sorts in-place by version (numeric-aware), falling back to build date then ingestion time.
func sortCandidates(candidates []changelogCandidate) {
	sort.Slice(candidates, func(i, j int) bool {
		return candidateLess(candidates, i, j)
	})
}

func candidateLess(candidates []changelogCandidate, i, j int) bool {
	vi := candidates[i].sbom.SubjectVersion.String
	vj := candidates[j].sbom.SubjectVersion.String
	hasVI := candidates[i].sbom.SubjectVersion.Valid && vi != ""
	hasVJ := candidates[j].sbom.SubjectVersion.Valid && vj != ""

	if hasVI && hasVJ {
		if cmp := compareVersionStrings(vi, vj); cmp != 0 {
			return cmp < 0
		}
	}

	ei := candidateEffectiveTime(candidates[i])
	ej := candidateEffectiveTime(candidates[j])
	if !ei.Equal(ej) {
		return ei.Before(ej)
	}
	return candidates[i].sbom.CreatedAt.Time.Before(candidates[j].sbom.CreatedAt.Time)
}

func candidateEffectiveTime(c changelogCandidate) time.Time {
	if c.buildDate != nil {
		return *c.buildDate
	}
	return c.sbom.CreatedAt.Time
}

// enrichmentMeta holds OCI metadata extracted from an SBOM's oci-metadata enrichment.
type enrichmentMeta struct {
	buildDate    *time.Time
	architecture string
}

// buildEnrichmentMetaMap fetches enrichments for all SBOMs of an artifact and returns
// a map of sbom UUID → enrichmentMeta. "oci-metadata" takes precedence over "user".
func buildEnrichmentMetaMap(ctx context.Context, q *repository.Queries, artifactID pgtype.UUID) map[pgtype.UUID]enrichmentMeta {
	m := make(map[pgtype.UUID]enrichmentMeta)

	rows, err := q.ListSBOMEnrichmentsByArtifact(ctx, artifactID)
	if err != nil {
		return m
	}

	type rawMeta struct {
		Created      *time.Time `json:"created"`
		Architecture string     `json:"architecture"`
	}

	// Two-pass: collect user enrichments first, then overwrite with oci-metadata.
	user := make(map[pgtype.UUID]enrichmentMeta)
	oci := make(map[pgtype.UUID]enrichmentMeta)
	for _, row := range rows {
		if len(row.Data) == 0 {
			continue
		}
		var raw rawMeta
		if err := json.Unmarshal(row.Data, &raw); err != nil {
			slog.Warn("changelog: skipping malformed enrichment data", "enricher", row.EnricherName, "err", err)
			continue
		}
		entry := enrichmentMeta{buildDate: raw.Created, architecture: raw.Architecture}
		switch row.EnricherName {
		case "oci-metadata":
			oci[row.SbomID] = entry
		case "user":
			user[row.SbomID] = entry
		}
	}

	for id, e := range user {
		m[id] = e
	}
	for id, e := range oci {
		m[id] = e
	}

	return m
}

// compareVersionStrings compares two version strings numerically.
// Segments are split on "." and "-" and compared as integers when possible,
// lexicographically otherwise. Returns -1, 0, or +1.
func compareVersionStrings(a, b string) int {
	splitVersion := func(s string) []string {
		return strings.FieldsFunc(strings.ReplaceAll(s, "-", "."), func(r rune) bool {
			return r == '.'
		})
	}
	pa, pb := splitVersion(a), splitVersion(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		ia, aerr := strconv.Atoi(pa[i])
		ib, berr := strconv.Atoi(pb[i])
		if aerr == nil && berr == nil {
			if ia != ib {
				if ia < ib {
					return -1
				}
				return 1
			}
		} else {
			if pa[i] != pb[i] {
				if pa[i] < pb[i] {
					return -1
				}
				return 1
			}
		}
	}
	if len(pa) != len(pb) {
		if len(pa) < len(pb) {
			return -1
		}
		return 1
	}
	return 0
}

// laterThan reports whether (bd1, t1) is chronologically after (bd2, t2).
// Build date is preferred; ingestion time is the tiebreaker.
func laterThan(bd1 *time.Time, t1 time.Time, bd2 *time.Time, t2 time.Time) bool {
	eff1, eff2 := t1, t2
	if bd1 != nil {
		eff1 = *bd1
	}
	if bd2 != nil {
		eff2 = *bd2
	}
	if !eff1.Equal(eff2) {
		return eff1.After(eff2)
	}
	return t1.After(t2)
}

// selectArch picks the architecture to use for the changelog timeline.
// If requested is non-empty and present, it wins. Otherwise a canonical
// preference order is applied, falling back to an arbitrary available arch.
func selectArch(requested string, available map[string]bool) string {
	if requested != "" && available[requested] {
		return requested
	}
	for _, p := range []string{"amd64", "arm64", "arm", "386", "s390x"} {
		if available[p] {
			return p
		}
	}
	for a := range available {
		return a
	}
	return ""
}

// nonEmptyStrPtr returns a pointer to s, or nil if s is empty.
func nonEmptyStrPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// componentIdentity holds the fields used to match a component across SBOMs.
type componentIdentity struct {
	version *string
	purl    *string
}

// buildComponentMap creates a map of component identity key → component info.
func buildComponentMap(rows []repository.ListSBOMComponentsRow) map[string]componentIdentity {
	m := make(map[string]componentIdentity, len(rows))
	for _, row := range rows {
		key := componentKey(row.Type, row.Name, row.GroupName, row.Purl)
		m[key] = componentIdentity{
			version: textToPtr(row.Version),
			purl:    textToPtr(row.Purl),
		}
	}
	return m
}

// componentKey generates the identity key for matching across SBOMs.
// Uses purl (without version) if available, otherwise (type, name, group).
func componentKey(typ, name string, group, purl pgtype.Text) string {
	if purl.Valid && purl.String != "" {
		return stripPurlVersion(purl.String)
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

// diffComponents computes the diff between two component maps.
func diffComponents(from, to SBOMRef, oldMap, newMap map[string]componentIdentity) ChangelogEntry {
	entry := ChangelogEntry{
		From:    from,
		To:      to,
		Changes: []ComponentDiff{},
	}

	// Find added and modified.
	for key, curr := range newMap {
		prev, exists := oldMap[key]
		if !exists {
			entry.Changes = append(entry.Changes, ComponentDiff{
				Type:    "added",
				Name:    nameFromKey(key),
				Group:   groupFromKey(key),
				Version: curr.version,
				Purl:    curr.purl,
			})
			entry.Summary.Added++
		} else if !versionsEqual(prev.version, curr.version) {
			entry.Changes = append(entry.Changes, ComponentDiff{
				Type:            "modified",
				Name:            nameFromKey(key),
				Group:           groupFromKey(key),
				Version:         curr.version,
				Purl:            curr.purl,
				PreviousVersion: prev.version,
			})
			entry.Summary.Modified++
		}
	}

	// Find removed.
	for key, prev := range oldMap {
		if _, exists := newMap[key]; !exists {
			entry.Changes = append(entry.Changes, ComponentDiff{
				Type:    "removed",
				Name:    nameFromKey(key),
				Group:   groupFromKey(key),
				Version: prev.version,
				Purl:    prev.purl,
			})
			entry.Summary.Removed++
		}
	}

	// Sort changes for deterministic output: removed, modified, added, then by name.
	sort.Slice(entry.Changes, func(i, j int) bool {
		order := map[string]int{"removed": 0, "modified": 1, "added": 2}
		if order[entry.Changes[i].Type] != order[entry.Changes[j].Type] {
			return order[entry.Changes[i].Type] < order[entry.Changes[j].Type]
		}
		return entry.Changes[i].Name < entry.Changes[j].Name
	})

	return entry
}

func sbomToRef(row repository.ListSBOMsByArtifactRow) SBOMRef {
	return SBOMRef{
		ID:             uuidToString(row.ID),
		SubjectVersion: textToPtr(row.SubjectVersion),
		CreatedAt:      row.CreatedAt.Time,
	}
}

func versionsEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
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
