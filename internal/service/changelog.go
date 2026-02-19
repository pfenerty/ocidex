package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Changelog represents the full changelog for an artifact.
type Changelog struct {
	ArtifactID string           `json:"artifactId"`
	Entries    []ChangelogEntry `json:"entries"`
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
func (s *searchService) DiffSBOMs(ctx context.Context, fromID, toID pgtype.UUID) (ChangelogEntry, error) {
	q := repository.New(s.pool)

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

// GetArtifactChangelog generates a changelog by diffing consecutive SBOMs for an artifact.
// SBOMs are ordered by OCI build date when available, falling back to ingestion time.
func (s *searchService) GetArtifactChangelog(ctx context.Context, artifactID pgtype.UUID, subjectVersion string) (Changelog, error) {
	q := repository.New(s.pool)

	// Fetch all SBOMs for this artifact.
	sboms, err := q.ListSBOMsByArtifact(ctx, repository.ListSBOMsByArtifactParams{
		ArtifactID:     artifactID,
		SubjectVersion: textOrNull(subjectVersion),
		RowLimit:       10000,
		RowOffset:      0,
	})
	if err != nil {
		return Changelog{}, fmt.Errorf("listing sboms: %w", err)
	}

	// Fetch enrichment build dates for all SBOMs in one query.
	buildDates := buildDateMap(ctx, q, artifactID)

	// Sort chronologically by build date (falling back to ingestion time).
	sort.Slice(sboms, func(i, j int) bool {
		ti := sbomSortTime(sboms[i], buildDates)
		tj := sbomSortTime(sboms[j], buildDates)
		return ti.Before(tj)
	})

	changelog := Changelog{
		ArtifactID: uuidToString(artifactID),
		Entries:    []ChangelogEntry{},
	}

	if len(sboms) < 2 {
		return changelog, nil
	}

	// Load components for the first SBOM.
	prevComps, err := q.ListSBOMComponents(ctx, sboms[0].ID)
	if err != nil {
		return Changelog{}, fmt.Errorf("listing components for sbom %s: %w", uuidToString(sboms[0].ID), err)
	}
	prevMap := buildComponentMap(prevComps)

	// Diff each consecutive pair.
	for i := 1; i < len(sboms); i++ {
		currComps, err := q.ListSBOMComponents(ctx, sboms[i].ID)
		if err != nil {
			return Changelog{}, fmt.Errorf("listing components for sbom %s: %w", uuidToString(sboms[i].ID), err)
		}
		currMap := buildComponentMap(currComps)

		fromRef := sbomToRef(sboms[i-1])
		fromRef.BuildDate = buildDates[sboms[i-1].ID]
		toRef := sbomToRef(sboms[i])
		toRef.BuildDate = buildDates[sboms[i].ID]

		entry := diffComponents(fromRef, toRef, prevMap, currMap)

		// Only include entries that have changes.
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

// buildDateMap fetches OCI metadata enrichments for all SBOMs of an artifact
// and returns a map of sbom UUID → build date (the "created" field).
func buildDateMap(ctx context.Context, q *repository.Queries, artifactID pgtype.UUID) map[pgtype.UUID]*time.Time {
	m := make(map[pgtype.UUID]*time.Time)

	rows, err := q.ListSBOMEnrichmentsByArtifact(ctx, artifactID)
	if err != nil {
		return m
	}

	for _, row := range rows {
		if row.EnricherName != "oci-metadata" || len(row.Data) == 0 {
			continue
		}
		var meta struct {
			Created *time.Time `json:"created"`
		}
		if err := json.Unmarshal(row.Data, &meta); err == nil && meta.Created != nil {
			m[row.SbomID] = meta.Created
		}
	}

	return m
}

// sbomSortTime returns the build date if available, otherwise the ingestion time.
func sbomSortTime(sbom repository.ListSBOMsByArtifactRow, buildDates map[pgtype.UUID]*time.Time) time.Time {
	if bd, ok := buildDates[sbom.ID]; ok && bd != nil {
		return *bd
	}
	return sbom.CreatedAt.Time
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
