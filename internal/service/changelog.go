package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

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

// Changelog represents the full changelog for an artifact.
type Changelog struct {
	ArtifactID             string           `json:"artifactId"`
	AvailableArchitectures []string         `json:"availableArchitectures"`
	AvailableFlavors       []string         `json:"availableFlavors"`
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
func buildPackageMap(rows []repository.ListSBOMPackagesRow) map[string]componentIdentity {
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

// changelogGroupKey identifies a unique (version, arch, flavor) triple for deduplication.
type changelogGroupKey struct{ version, arch, flavor string }

// changelogCandidate is a deduplicated SBOM representative for changelog diffing.
type changelogCandidate struct {
	sbom      repository.ListSBOMsByArtifactRow
	buildDate *time.Time
	arch      string
	flavor    string
}

// GetArtifactChangelog generates a changelog by diffing consecutive SBOMs for an artifact.
// SBOMs are grouped by (architecture, flavor), deduplicated by (version, arch, flavor), then
// diffed within the selected (arch, flavor) timeline.
func (s *searchService) GetArtifactChangelog(ctx context.Context, artifactID pgtype.UUID, subjectVersion, arch, flavor string, vis VisibilityFilter) (Changelog, error) {
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
	best, available, availableFlavors := deduplicateSBOMs(sboms, meta)
	selectedArch := selectArch(arch, available)
	selectedFlavor := selectFlavor(flavor, availableFlavors)
	candidates := filterByArchAndFlavor(best, selectedArch, selectedFlavor)
	sortCandidates(candidates)

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
		Entries:                []ChangelogEntry{},
	}

	if len(candidates) < 2 {
		return changelog, nil
	}

	prevComps, err := q.ListSBOMPackages(ctx, candidates[0].sbom.ID)
	if err != nil {
		return Changelog{}, fmt.Errorf("listing components for sbom %s: %w", uuidToString(candidates[0].sbom.ID), err)
	}
	prevMap := buildPackageMap(prevComps)

	for i := 1; i < len(candidates); i++ {
		currComps, err := q.ListSBOMPackages(ctx, candidates[i].sbom.ID)
		if err != nil {
			return Changelog{}, fmt.Errorf("listing components for sbom %s: %w", uuidToString(candidates[i].sbom.ID), err)
		}
		currMap := buildPackageMap(currComps)

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

// deduplicateSBOMs groups SBOMs by (version, arch, flavor) keeping the latest per group.
// Returns the best-per-group map, available architectures, and available flavors.
func deduplicateSBOMs(sboms []repository.ListSBOMsByArtifactRow, meta map[pgtype.UUID]enrichmentMeta) (map[changelogGroupKey]changelogCandidate, map[string]bool, map[string]bool) {
	best := map[changelogGroupKey]changelogCandidate{}
	available := map[string]bool{}
	availableFlavors := map[string]bool{}
	for _, sbom := range sboms {
		m := meta[sbom.ID]
		sv := sbom.SubjectVersion.String
		if !sbom.SubjectVersion.Valid || sv == "" {
			sv = uuidToString(sbom.ID)
		}
		flavorStr := sbom.Flavor.String
		key := changelogGroupKey{sv, m.architecture, flavorStr}
		prev, exists := best[key]
		if !exists || laterThan(m.buildDate, sbom.CreatedAt.Time, prev.buildDate, prev.sbom.CreatedAt.Time) {
			best[key] = changelogCandidate{sbom: sbom, buildDate: m.buildDate, arch: m.architecture, flavor: flavorStr}
		}
		available[m.architecture] = true
		availableFlavors[flavorStr] = true
	}
	return best, available, availableFlavors
}

// filterByArchAndFlavor returns candidates matching the given architecture and flavor.
func filterByArchAndFlavor(best map[changelogGroupKey]changelogCandidate, arch, flavor string) []changelogCandidate {
	var out []changelogCandidate
	for k, c := range best {
		if k.arch == arch && k.flavor == flavor {
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

// buildDepEdgeMaps constructs in-edge count and outgoing-edges adjacency from a dep list.
func buildDepEdgeMaps(deps []repository.ListDependenciesBySBOMRow) (inEdge map[string]int, outEdges map[string][]string) {
	inEdge = make(map[string]int, len(deps))
	outEdges = make(map[string][]string, len(deps))
	for _, d := range deps {
		inEdge[d.DependsOn]++
		outEdges[d.Ref] = append(outEdges[d.Ref], d.DependsOn)
	}
	return
}

// computeRootsAndDirect returns the ordered root bom-refs and the set of direct
// (one-hop-from-synthetic-root) bom-refs, given the edge maps and metadata bom-ref.
func computeRootsAndDirect(outEdges map[string][]string, inEdge map[string]int, metaBomRef string, toPkgs []repository.ListSBOMPackagesRow) (roots []string, directSet map[string]bool) {
	directSet = make(map[string]bool)
	if metaBomRef != "" && len(outEdges[metaBomRef]) > 0 {
		roots = make([]string, len(outEdges[metaBomRef]))
		copy(roots, outEdges[metaBomRef])
		for _, child := range roots {
			directSet[child] = true
		}
	} else {
		for _, p := range toPkgs {
			if p.BomRef.Valid && p.BomRef.String != metaBomRef && inEdge[p.BomRef.String] == 0 {
				roots = append(roots, p.BomRef.String)
			}
		}
	}
	bomRefName := make(map[string]string, len(toPkgs))
	for _, p := range toPkgs {
		if p.BomRef.Valid {
			bomRefName[p.BomRef.String] = p.Name
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		ni, nj := bomRefName[roots[i]], bomRefName[roots[j]]
		if ni != nj {
			return ni < nj
		}
		return roots[i] < roots[j]
	})
	return
}

// buildNodeLookups returns lookup maps: purl→nodeID, (name+\x00+group)→nodeID, bomRef→nodeID.
func buildNodeLookups(toPkgs []repository.ListSBOMPackagesRow) (nodeByPurl, nodeByNameGroup, bomRefToID map[string]string) {
	nodeByPurl = make(map[string]string, len(toPkgs))
	nodeByNameGroup = make(map[string]string, len(toPkgs))
	bomRefToID = make(map[string]string, len(toPkgs))
	for _, p := range toPkgs {
		id := uuidToString(p.ID)
		if p.Purl.Valid && p.Purl.String != "" {
			nodeByPurl[p.Purl.String] = id
		}
		nodeByNameGroup[p.Name+"\x00"+p.GroupName.String] = id
		if p.BomRef.Valid {
			bomRefToID[p.BomRef.String] = id
		}
	}
	return
}

// annotateNodeRefs sets NodeRef on each change by purl-first, name+group fallback.
func annotateNodeRefs(changes []ComponentDiff, nodeByPurl, nodeByNameGroup map[string]string) {
	for i := range changes {
		c := &changes[i]
		if c.Purl != nil && *c.Purl != "" {
			if id, ok := nodeByPurl[*c.Purl]; ok {
				idCopy := id
				c.NodeRef = &idCopy
				continue
			}
		}
		ng := c.Name + "\x00"
		if c.Group != nil {
			ng = c.Name + "\x00" + *c.Group
		}
		if id, ok := nodeByNameGroup[ng]; ok {
			idCopy := id
			c.NodeRef = &idCopy
		}
	}
}

// buildIDToChildren converts the bom-ref adjacency into a node-ID adjacency.
func buildIDToChildren(outEdges map[string][]string, bomRefToID map[string]string) map[string][]string {
	idToChildren := make(map[string][]string, len(bomRefToID))
	for bomRef, children := range outEdges {
		parentID, ok := bomRefToID[bomRef]
		if !ok {
			continue
		}
		for _, childRef := range children {
			if childID, ok2 := bomRefToID[childRef]; ok2 {
				idToChildren[parentID] = append(idToChildren[parentID], childID)
			}
		}
	}
	return idToChildren
}

// buildChangesByNodeID returns a map of nodeID → []direction for all changes with a NodeRef.
func buildChangesByNodeID(changes []ComponentDiff) map[string][]string {
	m := make(map[string][]string, len(changes))
	for _, c := range changes {
		if c.NodeRef != nil {
			m[*c.NodeRef] = append(m[*c.NodeRef], c.Direction)
		}
	}
	return m
}

// buildNodes constructs the ComponentSummary slice with IsDirect and DescendantChanges set.
func buildNodes(toPkgs []repository.ListSBOMPackagesRow, toID pgtype.UUID, directSet map[string]bool, idToChildren map[string][]string, changesByNodeID map[string][]string) []ComponentSummary {
	nodes := make([]ComponentSummary, 0, len(toPkgs))
	for _, p := range toPkgs {
		node := toComponentSummary(p.ID, toID, p.BomRef, p.Type, p.Name, p.GroupName, p.Version, p.Purl)
		if p.BomRef.Valid {
			node.IsDirect = directSet[p.BomRef.String]
		}
		nodes = append(nodes, node)
	}
	for i, n := range nodes {
		counts := dfsChangeCounts(n.ID, idToChildren, changesByNodeID, make(map[string]bool))
		if counts != (ChangeCounts{}) {
			nodes[i].DescendantChanges = &counts
		}
	}
	return nodes
}

// dfsChangeCounts aggregates change direction counts for a node's transitive descendants.
// Each DFS call uses its own visited set so a node is counted once per ancestor even
// when reachable via multiple paths (cycle-safe).
func dfsChangeCounts(nodeID string, idToChildren map[string][]string, changesByNodeID map[string][]string, visited map[string]bool) ChangeCounts {
	var counts ChangeCounts
	for _, childID := range idToChildren[nodeID] {
		if visited[childID] {
			continue
		}
		visited[childID] = true
		for _, dir := range changesByNodeID[childID] {
			addDirectionCount(&counts, dir)
		}
		sub := dfsChangeCounts(childID, idToChildren, changesByNodeID, visited)
		counts.Added += sub.Added
		counts.Removed += sub.Removed
		counts.Upgraded += sub.Upgraded
		counts.Downgraded += sub.Downgraded
		counts.Modified += sub.Modified
	}
	return counts
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

// debCharOrd returns the deb-policy ordering value for a byte (zero byte = end of string).
// Tilde < end-of-string < letters < non-letters (per Debian policy manual §5.6.12).
func debCharOrd(c byte) int {
	switch {
	case c == '~':
		return -1
	case c == 0:
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

// debReadAlpha consumes a non-digit prefix from s[i:] and returns the new index.
func debReadAlpha(s string, i int) ([]byte, int) {
	start := i
	for i < len(s) && (s[i] < '0' || s[i] > '9') {
		i++
	}
	return []byte(s[start:i]), i
}

// debReadDigit consumes a digit prefix from s[i:] and returns the integer value and new index.
func debReadDigit(s string, i int) (int, int) {
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	v, _ := strconv.Atoi(s[start:i])
	return v, i
}

// debCmpStr compares two Debian upstream/revision string segments using deb ordering.
func debCmpStr(a, b string) int {
	ai, bi := 0, 0
	for ai < len(a) || bi < len(b) {
		// Non-digit runs: compare character-by-character with deb char ordering.
		ra, ai2 := debReadAlpha(a, ai)
		rb, bi2 := debReadAlpha(b, bi)
		maxLen := len(ra)
		if len(rb) > maxLen {
			maxLen = len(rb)
		}
		for k := 0; k < maxLen; k++ {
			var ca, cb byte
			if k < len(ra) {
				ca = ra[k]
			}
			if k < len(rb) {
				cb = rb[k]
			}
			if oa, ob := debCharOrd(ca), debCharOrd(cb); oa != ob {
				if oa < ob {
					return -1
				}
				return 1
			}
		}
		ai, bi = ai2, bi2
		// Digit runs: compare numerically.
		an, ai3 := debReadDigit(a, ai)
		bn, bi3 := debReadDigit(b, bi)
		ai, bi = ai3, bi3
		if an != bn {
			if an < bn {
				return -1
			}
			return 1
		}
	}
	return 0
}

// debVersionCompare compares two Debian-format version strings.
// Handles epochs ("1:2.0" > "2.0"), tildes ("1.0~rc1" < "1.0"), and
// mixed alpha/numeric segments per Debian policy manual §5.6.12.
// Returns -1, 0, or +1.
func debVersionCompare(a, b string) int {
	parseDebVer := func(v string) (epoch int, ver, rev string) {
		if ci := strings.Index(v, ":"); ci != -1 {
			epoch, _ = strconv.Atoi(v[:ci])
			v = v[ci+1:]
		}
		ver = v
		if di := strings.LastIndex(v, "-"); di != -1 {
			rev = v[di+1:]
			ver = v[:di]
		}
		return
	}
	ea, va, ra := parseDebVer(a)
	eb, vb, rb := parseDebVer(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := debCmpStr(va, vb); c != 0 {
		return c
	}
	return debCmpStr(ra, rb)
}

// addDirectionCount increments the appropriate field of counts based on direction.
func addDirectionCount(counts *ChangeCounts, dir string) {
	switch dir {
	case dirAdded:
		counts.Added++
	case dirRemoved:
		counts.Removed++
	case dirUpgraded:
		counts.Upgraded++
	case dirDowngraded:
		counts.Downgraded++
	default:
		counts.Modified++
	}
}

// addSummaryCount increments the appropriate field of summary based on direction.
func addSummaryCount(s *ChangeSummary, dir string) {
	switch dir {
	case dirAdded:
		s.Added++
	case dirRemoved:
		s.Removed++
	case dirUpgraded:
		s.Upgraded++
	case dirDowngraded:
		s.Downgraded++
	default:
		s.Modified++
	}
}

// classifyDirection returns the direction of a ComponentDiff using deb-version-aware
// comparison. Returns one of the dir* constants.
func classifyDirection(d ComponentDiff) string {
	if d.Type != dirModified {
		return d.Type
	}
	if d.PreviousVersion == nil || d.Version == nil {
		return dirModified
	}
	cmp := debVersionCompare(*d.Version, *d.PreviousVersion)
	switch {
	case cmp > 0:
		return dirUpgraded
	case cmp < 0:
		return dirDowngraded
	default:
		return dirModified
	}
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

// selectFlavor picks the flavor to use for the changelog timeline.
// If requested is non-empty and present, it wins. Otherwise the first alphabetically
// (excluding flavorUnknown) is preferred; flavorUnknown is used as a last resort.
func selectFlavor(requested string, available map[string]bool) string {
	if requested != "" && available[requested] {
		return requested
	}
	var keys []string
	for f := range available {
		if f != flavorUnknown {
			keys = append(keys, f)
		}
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		return keys[0]
	}
	if available[flavorUnknown] {
		return flavorUnknown
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
				Name:    nameFromKey(key),
				Group:   groupFromKey(key),
				Version: curr.version,
				Purl:    curr.purl,
			})
		} else if !versionsEqual(prev.version, curr.version) {
			entry.Changes = append(entry.Changes, ComponentDiff{
				Type:            dirModified,
				Name:            nameFromKey(key),
				Group:           groupFromKey(key),
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
				Name:    nameFromKey(key),
				Group:   groupFromKey(key),
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
