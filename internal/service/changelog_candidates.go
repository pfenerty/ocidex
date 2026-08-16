// Choosing which SBOMs a changelog is built from: one winner per
// (version, arch, flavor) group, then the arch/flavor axes narrowed to a
// single comparable series. Split out of changelog.go — the selection rules
// are independent of how two chosen SBOMs are then diffed.

package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/enrichment/names"
	"github.com/pfenerty/ocidex/internal/repository"
)

// changelogGroupKey identifies a unique (version, arch, flavor) triple for deduplication.
type changelogGroupKey struct{ version, arch, flavor string }

// changelogCandidate is a deduplicated SBOM representative for changelog diffing.
type changelogCandidate struct {
	sbom      repository.ListSBOMsByArtifactRow
	buildDate *time.Time
	arch      string
	flavor    string
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

// groupsHaveSemver reports whether any deduplicated group has a semver version.
func groupsHaveSemver(best map[changelogGroupKey]changelogCandidate) bool {
	for k := range best {
		if isSemver(k.version) {
			return true
		}
	}
	return false
}

// filterSemverCandidates keeps only candidates whose subject version is semver.
func filterSemverCandidates(candidates []changelogCandidate) []changelogCandidate {
	out := candidates[:0:0]
	for _, c := range candidates {
		if c.sbom.SubjectVersion.Valid && isSemver(c.sbom.SubjectVersion.String) {
			out = append(out, c)
		}
	}
	return out
}

// sortCandidates sorts in-place. In SortSemver mode it orders by semantic-version
// precedence (build time breaks ties); otherwise it orders purely by build time,
// falling back to ingestion time.
func sortCandidates(candidates []changelogCandidate, mode VersionSortMode) {
	sort.Slice(candidates, func(i, j int) bool {
		return candidateLess(candidates, i, j, mode)
	})
}

func candidateLess(candidates []changelogCandidate, i, j int, mode VersionSortMode) bool {
	if mode == SortSemver {
		vi := candidates[i].sbom.SubjectVersion.String
		vj := candidates[j].sbom.SubjectVersion.String
		hasVI := candidates[i].sbom.SubjectVersion.Valid && vi != ""
		hasVJ := candidates[j].sbom.SubjectVersion.Valid && vj != ""
		if hasVI && hasVJ {
			if cmp := compareSemver(vi, vj); cmp != 0 {
				return cmp < 0
			}
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
		case names.OCIMetadata:
			oci[row.SbomID] = entry
		case names.User:
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

func sbomToRef(row repository.ListSBOMsByArtifactRow) SBOMRef {
	return SBOMRef{
		ID:             uuidToString(row.ID),
		SubjectVersion: textToPtr(row.SubjectVersion),
		CreatedAt:      row.CreatedAt.Time,
	}
}
