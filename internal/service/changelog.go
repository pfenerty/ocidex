package service

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Changelog represents the full changelog for an artifact.
type Changelog struct {
	ArtifactID             string   `json:"artifactId"`
	AvailableArchitectures []string `json:"availableArchitectures"`
	AvailableFlavors       []string `json:"availableFlavors"`
	// HasSemver reports whether the artifact has any semver-parseable version,
	// so the client can default the Semver/All toggle.
	HasSemver bool `json:"hasSemver"`
	// ResolvedMode is the concrete sort mode used ("semver" or "all"), after
	// resolving an auto request.
	ResolvedMode string           `json:"resolvedMode"`
	Entries      []ChangelogEntry `json:"entries"`
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
	Flavor         *string    `json:"flavor,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	BuildDate      *time.Time `json:"buildDate,omitempty"`
}

// ChangeSummary counts the number of changes by type.
type ChangeSummary struct {
	Added      int `json:"added"`
	Removed    int `json:"removed"`
	Upgraded   int `json:"upgraded"`
	Downgraded int `json:"downgraded"`
	Modified   int `json:"modified"`
}

// Change direction constants — values for ComponentDiff.Direction.
const (
	dirAdded      = "added"
	dirRemoved    = "removed"
	dirUpgraded   = "upgraded"
	dirDowngraded = "downgraded"
	dirModified   = "modified"
)

// ComponentDiff represents a single component change between two SBOMs.
type ComponentDiff struct {
	Type            string  `json:"type"`      // "added", "removed", "modified"
	Direction       string  `json:"direction"` // "added", "removed", "upgraded", "downgraded", "modified"
	Name            string  `json:"name"`
	Group           *string `json:"group,omitempty"`
	Version         *string `json:"version,omitempty"`
	Purl            *string `json:"purl,omitempty"`
	PreviousVersion *string `json:"previousVersion,omitempty"`
	NodeRef         *string `json:"nodeRef,omitempty"` // ID of the matching ComponentSummary node
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

// DiffSBOMsWithTree computes the diff between two SBOMs and returns it alongside
// the non-file dependency graph of the "to" SBOM for tree-structured rendering.
func (s *searchService) DiffSBOMsWithTree(ctx context.Context, fromID, toID pgtype.UUID, vis VisibilityFilter) (DiffTree, error) {
	q := repository.New(s.db)

	for _, id := range []pgtype.UUID{fromID, toID} {
		visible, err := q.IsSBOMVisible(ctx, repository.IsSBOMVisibleParams{
			ID:      id,
			UserID:  vis.UserID,
			IsAdmin: visAdminBool(vis),
		})
		if err != nil {
			return DiffTree{}, fmt.Errorf("checking sbom visibility: %w", err)
		}
		if !visible {
			return DiffTree{}, ErrNotFound
		}
	}

	fromSBOM, err := q.GetSBOMRef(ctx, fromID)
	if err != nil {
		return DiffTree{}, fmt.Errorf("getting from sbom: %w", err)
	}
	toSBOM, err := q.GetSBOMRef(ctx, toID)
	if err != nil {
		return DiffTree{}, fmt.Errorf("getting to sbom: %w", err)
	}

	// Use non-file packages for both sides so the diff only covers real packages.
	fromPkgs, err := q.ListSBOMPackages(ctx, fromID)
	if err != nil {
		return DiffTree{}, fmt.Errorf("listing from packages: %w", err)
	}
	toPkgs, err := q.ListSBOMPackages(ctx, toID)
	if err != nil {
		return DiffTree{}, fmt.Errorf("listing to packages: %w", err)
	}

	deps, err := q.ListDependenciesBySBOM(ctx, toID)
	if err != nil {
		return DiffTree{}, fmt.Errorf("listing dependencies: %w", err)
	}

	fromRef := SBOMRef{
		ID:             uuidToString(fromSBOM.ID),
		SubjectVersion: textToPtr(fromSBOM.SubjectVersion),
		CreatedAt:      fromSBOM.CreatedAt.Time,
		BuildDate:      interfaceToTimePtr(fromSBOM.BuildDate),
		Architecture:   interfaceToStringPtr(fromSBOM.Architecture),
	}
	toRef := SBOMRef{
		ID:             uuidToString(toSBOM.ID),
		SubjectVersion: textToPtr(toSBOM.SubjectVersion),
		CreatedAt:      toSBOM.CreatedAt.Time,
		BuildDate:      interfaceToTimePtr(toSBOM.BuildDate),
		Architecture:   interfaceToStringPtr(toSBOM.Architecture),
	}

	// Fetch the metadata.component.bom-ref for root + isDirect computation (B5, B6).
	rawMetaBomRef, err := q.GetSBOMMetadataBomRef(ctx, toID)
	if err != nil {
		return DiffTree{}, fmt.Errorf("getting metadata bom-ref: %w", err)
	}
	var metaBomRef string
	if rawMetaBomRef != nil {
		if s, ok := rawMetaBomRef.(string); ok {
			metaBomRef = s
		}
	}

	entry := diffComponents(fromRef, toRef, buildPackageMap(fromPkgs), buildPackageMap(toPkgs))

	inEdge, outEdges := buildDepEdgeMaps(deps)
	roots, directSet := computeRootsAndDirect(outEdges, inEdge, metaBomRef, toPkgs)
	nodeByPurl, nodeByNameGroup, bomRefToID := buildNodeLookups(toPkgs)
	annotateNodeRefs(entry.Changes, nodeByPurl, nodeByNameGroup)
	idToChildren := buildIDToChildren(outEdges, bomRefToID)
	changesByNodeID := buildChangesByNodeID(entry.Changes)

	nodes := buildNodes(toPkgs, toID, directSet, idToChildren, changesByNodeID)

	edges := make([]DependencyEdge, 0, len(deps))
	for _, d := range deps {
		edges = append(edges, DependencyEdge{From: d.Ref, To: d.DependsOn})
	}

	return DiffTree{
		From:    entry.From,
		To:      entry.To,
		Summary: entry.Summary,
		Changes: entry.Changes,
		Nodes:   nodes,
		Edges:   edges,
		Roots:   roots,
	}, nil
}

// buildPackageMap creates a component identity map from ListSBOMPackages rows.
// packagesForSBOMs fetches the packages for all candidate SBOMs in a single
// query and groups them by SBOM id, replacing a per-version N+1.
func (s *searchService) packagesForSBOMs(ctx context.Context, q *repository.Queries, candidates []changelogCandidate) (map[pgtype.UUID][]repository.ListSBOMPackagesRow, error) {
	ids := make([]pgtype.UUID, 0, len(candidates))
	for _, c := range candidates {
		ids = append(ids, c.sbom.ID)
	}

	rows, err := q.ListSBOMPackagesBySBOMIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("listing components for sboms: %w", err)
	}

	bySBOM := make(map[pgtype.UUID][]repository.ListSBOMPackagesRow, len(candidates))
	for _, r := range rows {
		bySBOM[r.SbomID] = append(bySBOM[r.SbomID], repository.ListSBOMPackagesRow{
			ID:        r.ID,
			BomRef:    r.BomRef,
			Type:      r.Type,
			Name:      r.Name,
			GroupName: r.GroupName,
			Version:   r.Version,
			Purl:      r.Purl,
		})
	}
	return bySBOM, nil
}

// GetArtifactChangelog generates a changelog by diffing consecutive SBOMs for an artifact.
// SBOMs are grouped by (architecture, flavor), deduplicated by (version, arch, flavor), then
// diffed within the selected (arch, flavor) timeline.
func (s *searchService) GetArtifactChangelog(ctx context.Context, artifactID pgtype.UUID, subjectVersion, arch, flavor string, mode VersionSortMode, vis VisibilityFilter) (Changelog, error) {
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

	// Changelog needs every SBOM for the artifact (no cursor); cap defensively.
	sboms, err := q.ListSBOMsByArtifact(ctx, repository.ListSBOMsByArtifactParams{
		ArtifactID:     artifactID,
		SubjectVersion: textOrNull(subjectVersion),
		UserID:         vis.UserID,
		IsAdmin:        visAdminBool(vis),
		HasCursor:      pgtype.Bool{Bool: false, Valid: true},
		RowLimit:       10000,
	})
	if err != nil {
		return Changelog{}, fmt.Errorf("listing sboms: %w", err)
	}

	meta := buildEnrichmentMetaMap(ctx, q, artifactID)
	best, available, availableFlavors := deduplicateSBOMs(sboms, meta)
	selectedArch := selectArch(arch, available)
	selectedFlavor := selectFlavor(flavor, availableFlavors)

	// hasSemver reflects the whole artifact (any arch/flavor), so switching the
	// selected timeline never flips the default Semver/All toggle.
	hasSemver := groupsHaveSemver(best)
	resolved := resolveSortMode(mode, hasSemver)

	candidates := filterByArchAndFlavor(best, selectedArch, selectedFlavor)
	if resolved == SortSemver {
		candidates = filterSemverCandidates(candidates)
	}
	sortCandidates(candidates, resolved)

	arches := make([]string, 0, len(available))
	for a := range available {
		arches = append(arches, a)
	}
	sort.Strings(arches)

	flavors := make([]string, 0, len(availableFlavors))
	for f := range availableFlavors {
		flavors = append(flavors, f)
	}
	sort.Strings(flavors)

	changelog := Changelog{
		ArtifactID:             uuidToString(artifactID),
		AvailableArchitectures: arches,
		AvailableFlavors:       flavors,
		HasSemver:              hasSemver,
		ResolvedMode:           string(resolved),
		Entries:                []ChangelogEntry{},
	}

	if len(candidates) < 2 {
		return changelog, nil
	}

	// Fetch packages for every candidate SBOM in a single round-trip rather than
	// one query per version (the old N+1).
	pkgsBySBOM, err := s.packagesForSBOMs(ctx, q, candidates)
	if err != nil {
		return Changelog{}, err
	}

	prevMap := buildPackageMap(pkgsBySBOM[candidates[0].sbom.ID])

	for i := 1; i < len(candidates); i++ {
		currMap := buildPackageMap(pkgsBySBOM[candidates[i].sbom.ID])

		fromRef := sbomToRef(candidates[i-1].sbom)
		fromRef.BuildDate = candidates[i-1].buildDate
		fromRef.Architecture = nonEmptyStrPtr(candidates[i-1].arch)
		fromRef.Flavor = nonEmptyStrPtr(candidates[i-1].flavor)
		toRef := sbomToRef(candidates[i].sbom)
		toRef.BuildDate = candidates[i].buildDate
		toRef.Architecture = nonEmptyStrPtr(candidates[i].arch)
		toRef.Flavor = nonEmptyStrPtr(candidates[i].flavor)

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
