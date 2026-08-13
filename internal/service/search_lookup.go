package service

import (
	"context"
	"fmt"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Qualifier keys used in LookupCandidate.Qualifiers. They match the resolver
// endpoints' query parameter names so a caller can feed a candidate's
// qualifiers straight back into the next, narrower request.
const (
	qualifierName     = "name"
	qualifierType     = "type"
	qualifierGroup    = "group"
	qualifierArtifact = "artifact"
	qualifierVersion  = "version"
	qualifierArch     = "arch"
	qualifierFlavor   = "flavor"
	qualifierDigest   = "digest"
)

// LookupCandidate is one visible match from a name-keyed lookup (ADR-042 R5).
//
// Qualifiers carries the R4 ladder values that distinguish this candidate from
// its siblings, so a caller that got a 409 can retry one rung further down the
// ladder without a second discovery round trip. Its keys are the query
// parameter names of the resolver that produced it.
type LookupCandidate struct {
	ID         string            `json:"id" doc:"Canonical UUID of the matching resource"`
	Qualifiers map[string]string `json:"qualifiers" doc:"Qualifier values that distinguish this candidate, keyed by resolver query parameter"`
}

// ArtifactLookupQuery is the ADR-042 R4 qualifier ladder for artifact lookup:
// name -> +type -> +group. Empty qualifiers are wildcards, not empty-string
// matches, so an omitted rung widens the query rather than pinning it.
type ArtifactLookupQuery struct {
	Name  string
	Type  string
	Group string
}

// LookupArtifact returns every artifact visible to the caller that matches the
// R4 ladder. Counting — and therefore the 200/404/409 decision of ADR-042 R5 —
// is the caller's job; this returns candidates already filtered for visibility
// so a private artifact can never influence that count.
func (s *searchService) LookupArtifact(ctx context.Context, query ArtifactLookupQuery, vis VisibilityFilter) ([]LookupCandidate, error) {
	q := repository.New(s.db)

	rows, err := q.LookupArtifacts(ctx, repository.LookupArtifactsParams{
		Name:      query.Name,
		Type:      textOrNull(query.Type),
		GroupName: textOrNull(query.Group),
		UserID:    vis.UserID,
		IsAdmin:   visAdminBool(vis),
	})
	if err != nil {
		return nil, fmt.Errorf("looking up artifact: %w", err)
	}

	candidates := make([]LookupCandidate, 0, len(rows))
	for _, row := range rows {
		candidates = append(candidates, LookupCandidate{
			ID: uuidToString(row.ID),
			Qualifiers: map[string]string{
				qualifierName:  row.Name,
				qualifierType:  row.Type,
				qualifierGroup: row.GroupName.String,
			},
		})
	}
	return candidates, nil
}

// LookupLicense resolves an SPDX identifier to a license (ADR-042 R3).
//
// spdx_id is already a natural key — idx_license_spdx_id is UNIQUE WHERE NOT
// NULL — so there is no qualifier ladder and no ambiguity to resolve, which is
// why this returns a single license rather than candidates. It reuses
// ListLicenses's existing spdx_id filter rather than adding a query that would
// have to duplicate its visibility-aware component count.
func (s *searchService) LookupLicense(ctx context.Context, spdxID string, vis VisibilityFilter) (LicenseCount, error) {
	page, err := s.ListLicenses(ctx, LicenseFilter{SpdxID: spdxID, Limit: 1, Visibility: vis})
	if err != nil {
		return LicenseCount{}, err
	}
	if len(page.Data) == 0 {
		return LicenseCount{}, ErrNotFound
	}
	return page.Data[0], nil
}

// SBOMLookupQuery is the ADR-042 R4 qualifier ladder for SBOM lookup:
// artifact+version -> +arch -> +flavor. Digest is the alternative form; it is
// unique by construction (idx_sbom_digest) and so is never combined with the
// ladder by callers, though nothing here forbids it.
type SBOMLookupQuery struct {
	Artifact string
	Version  string
	Arch     string
	Flavor   string
	Digest   string
}

// LookupSBOM returns every SBOM visible to the caller that matches the query.
// As with LookupArtifact, counting is the caller's job and the rows returned
// are already visibility-filtered.
func (s *searchService) LookupSBOM(ctx context.Context, query SBOMLookupQuery, vis VisibilityFilter) ([]LookupCandidate, error) {
	q := repository.New(s.db)

	rows, err := q.LookupSBOMs(ctx, repository.LookupSBOMsParams{
		Digest:   textOrNull(query.Digest),
		Artifact: textOrNull(query.Artifact),
		Version:  textOrNull(query.Version),
		Arch:     textOrNull(query.Arch),
		Flavor:   textOrNull(query.Flavor),
		UserID:   vis.UserID,
		IsAdmin:  visAdminBool(vis),
	})
	if err != nil {
		return nil, fmt.Errorf("looking up sbom: %w", err)
	}

	candidates := make([]LookupCandidate, 0, len(rows))
	for _, row := range rows {
		candidates = append(candidates, LookupCandidate{
			ID: uuidToString(row.ID),
			Qualifiers: map[string]string{
				qualifierArtifact: row.ArtifactName.String,
				qualifierVersion:  row.VersionKey.String,
				qualifierArch:     row.Architecture,
				qualifierFlavor:   row.Flavor.String,
				qualifierDigest:   row.Digest.String,
			},
		})
	}
	return candidates, nil
}
