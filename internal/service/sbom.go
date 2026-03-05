// Package service contains business logic interfaces and implementations.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/repository"
)

// IngestParams carries supplemental metadata for SBOM ingestion.
// Fields take precedence over BOM-extracted values when set.
type IngestParams struct {
	Version      string // image tag / subject version
	Architecture string // e.g. "amd64"
	BuildDate    string // RFC3339 or date string
}

// SBOMService defines the business logic for SBOM ingestion and management.
type SBOMService interface {
	Ingest(ctx context.Context, bom *cdx.BOM, rawJSON []byte, params IngestParams) (pgtype.UUID, error)
	DeleteSBOM(ctx context.Context, id pgtype.UUID) error
	DeleteArtifact(ctx context.Context, id pgtype.UUID) error
}

// DigestValidator validates that a container image digest points to a single
// image manifest rather than a manifest list (image index).
type DigestValidator interface {
	ValidateDigest(ctx context.Context, imageName, digest string) error
}

type sbomService struct {
	pool            *pgxpool.Pool
	publisher       event.Publisher
	digestValidator DigestValidator
}

// NewSBOMService creates a new SBOMService. The publisher and validator
// are optional; if nil, the corresponding functionality is skipped.
func NewSBOMService(pool *pgxpool.Pool, publisher event.Publisher, validator DigestValidator) SBOMService {
	return &sbomService{pool: pool, publisher: publisher, digestValidator: validator}
}

// artifactInfo holds the resolved artifact identity extracted from a BOM's metadata.
type artifactInfo struct {
	artifactID     pgtype.UUID
	subjectVersion pgtype.Text
	digest         pgtype.Text
}

// resolveArtifact extracts artifact identity from the BOM metadata and upserts
// the artifact row. It returns the artifact ID, subject version, and image digest.
func resolveArtifact(ctx context.Context, q *repository.Queries, bom *cdx.BOM, params IngestParams) (artifactInfo, error) {
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return artifactInfo{}, nil
	}

	mc := bom.Metadata.Component
	var digest pgtype.Text

	// Normalize container image names: strip digest suffix so that
	// "docker.io/ubuntu@sha256:abc..." and "docker.io/ubuntu" resolve
	// to the same artifact. Capture the digest for indexing.
	name := mc.Name
	if mc.Type == cdx.ComponentTypeContainer {
		if idx := strings.Index(name, "@sha256:"); idx != -1 {
			digest = pgtype.Text{String: name[idx+1:], Valid: true}
			name = name[:idx]
		}
	}

	// Also check metadata.component.version for digest (e.g. "sha256:abc...").
	if !digest.Valid && mc.Version != "" && strings.HasPrefix(mc.Version, "sha256:") {
		digest = pgtype.Text{String: mc.Version, Valid: true}
	}

	// Container SBOMs must include a digest for reproducibility and enrichment.
	if mc.Type == cdx.ComponentTypeContainer && !digest.Valid {
		return artifactInfo{}, &ValidationError{
			Message: fmt.Sprintf("container SBOM for %q missing digest: include digest in component name (@sha256:...) or version", name),
		}
	}

	artifactID, err := q.UpsertArtifact(ctx, repository.UpsertArtifactParams{
		Type:      string(mc.Type),
		Name:      name,
		GroupName: textOrNull(mc.Group),
		Purl:      textOrNull(mc.PackageURL),
		Cpe:       textOrNull(mc.CPE),
	})
	if err != nil {
		return artifactInfo{}, fmt.Errorf("upserting artifact: %w", err)
	}

	return artifactInfo{
		artifactID:     artifactID,
		subjectVersion: resolveSubjectVersion(bom, params),
		digest:         digest,
	}, nil
}

// Ingest decomposes a CycloneDX BOM and persists it in a single transaction.
func (s *sbomService) Ingest(ctx context.Context, bom *cdx.BOM, rawJSON []byte, params IngestParams) (pgtype.UUID, error) {
	// Validate container digests before starting the transaction.
	// This makes a network call to the registry, so it runs outside the tx.
	if err := s.validateContainerDigest(ctx, bom); err != nil {
		return pgtype.UUID{}, err
	}

	// Idempotency check: if we already have an SBOM for this digest, skip ingestion.
	if digest := extractDigestFromBOM(bom); digest != "" {
		existing, err := repository.New(s.pool).GetSBOMByDigest(ctx, pgtype.Text{String: digest, Valid: true})
		if err == nil {
			slog.InfoContext(ctx, "skipping duplicate sbom ingestion", "digest", digest, "existing_id", existing)
			return existing, nil
		}
		// pgx.ErrNoRows → proceed normally; other errors are ignored (UNIQUE index is the backstop)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on committed tx is a no-op

	q := repository.New(tx)

	info, err := resolveArtifact(ctx, q, bom, params)
	if err != nil {
		return pgtype.UUID{}, err
	}

	arch := resolveArchitecture(bom, params)
	bd := resolveBuildDate(bom, params)

	// Mandatory validation for container SBOMs.
	if bom.Metadata != nil && bom.Metadata.Component != nil &&
		bom.Metadata.Component.Type == cdx.ComponentTypeContainer {
		var missing []string
		if !info.subjectVersion.Valid {
			missing = append(missing, "subject_version")
		}
		if arch == "" {
			missing = append(missing, "architecture")
		}
		if bd == "" {
			missing = append(missing, "build_date")
		}
		if len(missing) > 0 {
			return pgtype.UUID{}, &ValidationError{
				Message: fmt.Sprintf("container SBOM missing required metadata: %s", strings.Join(missing, ", ")),
			}
		}
	}

	sbomRow, err := q.InsertSBOM(ctx, repository.InsertSBOMParams{
		SerialNumber:   textOrNull(bom.SerialNumber),
		SpecVersion:    bom.SpecVersion.String(),
		Version:        int32(bom.Version), //nolint:gosec // CycloneDX version is always small
		RawBom:         rawJSON,
		ArtifactID:     info.artifactID,
		SubjectVersion: info.subjectVersion,
		Digest:         info.digest,
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("inserting sbom: %w", err)
	}

	slog.InfoContext(ctx, "persisting sbom",
		"sbom_id", sbomRow.ID,
		"spec_version", sbomRow.SpecVersion,
		"artifact_id", info.artifactID,
	)

	// Write "user" enrichment so metadata is immediately visible in queries,
	// before the async OCI enricher runs.
	if arch != "" || bd != "" || info.subjectVersion.Valid {
		data := map[string]string{}
		if arch != "" {
			data["architecture"] = arch
		}
		if bd != "" {
			data["created"] = bd
		}
		if info.subjectVersion.Valid {
			data["imageVersion"] = info.subjectVersion.String
		}
		dataJSON, _ := json.Marshal(data)
		if err := q.UpsertEnrichment(ctx, repository.UpsertEnrichmentParams{
			SbomID:       sbomRow.ID,
			EnricherName: "user",
			Status:       "success",
			Data:         dataJSON,
		}); err != nil {
			return pgtype.UUID{}, fmt.Errorf("writing user enrichment: %w", err)
		}

		// Mark as sufficiently enriched when both version and architecture are present.
		if arch != "" && info.subjectVersion.Valid {
			if err := q.UpdateSBOMEnrichmentSufficient(ctx, repository.UpdateSBOMEnrichmentSufficientParams{
				ID:                   sbomRow.ID,
				EnrichmentSufficient: true,
			}); err != nil {
				return pgtype.UUID{}, fmt.Errorf("updating enrichment sufficiency: %w", err)
			}
		}
	}

	if bom.Components != nil {
		if err := s.insertComponents(ctx, q, sbomRow.ID, pgtype.UUID{}, *bom.Components); err != nil {
			return pgtype.UUID{}, err
		}
	}

	if bom.Dependencies != nil {
		if err := s.insertDependencies(ctx, q, sbomRow.ID, *bom.Dependencies); err != nil {
			return pgtype.UUID{}, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return pgtype.UUID{}, fmt.Errorf("committing transaction: %w", err)
	}

	// Publish event after successful commit so extensions (enrichment, audit, etc.) can react.
	if s.publisher != nil && sbomRow.ID.Valid {
		s.publisher.Publish(ctx, event.SBOMIngested, event.SBOMIngestedData{
			SBOMID:         sbomRow.ID,
			ArtifactType:   string(bom.Metadata.Component.Type),
			ArtifactName:   bom.Metadata.Component.Name,
			Digest:         info.digest.String,
			SubjectVersion: info.subjectVersion.String,
		})
	}

	return sbomRow.ID, nil
}

// DeleteSBOM removes an SBOM and all its associated data (components, hashes,
// licenses, dependencies, external references) via ON DELETE CASCADE.
func (s *sbomService) DeleteSBOM(ctx context.Context, id pgtype.UUID) error {
	q := repository.New(s.pool)
	rows, err := q.DeleteSBOM(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting sbom: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	if s.publisher != nil {
		s.publisher.Publish(ctx, event.SBOMDeleted, event.SBOMDeletedData{SBOMID: id})
	}
	return nil
}

// DeleteArtifact removes an artifact and all its SBOMs in a transaction.
// SBOMs are deleted first since the FK does not cascade.
func (s *sbomService) DeleteArtifact(ctx context.Context, id pgtype.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on committed tx is a no-op

	q := repository.New(tx)

	// Delete child SBOMs first (cascades to components, deps, etc.).
	if _, err := q.DeleteSBOMsByArtifact(ctx, id); err != nil {
		return fmt.Errorf("deleting artifact sboms: %w", err)
	}

	rows, err := q.DeleteArtifact(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting artifact: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	if s.publisher != nil {
		s.publisher.Publish(ctx, event.ArtifactDeleted, event.ArtifactDeletedData{ArtifactID: id})
	}
	return nil
}

func (s *sbomService) insertComponents(
	ctx context.Context,
	q *repository.Queries,
	sbomID pgtype.UUID,
	parentID pgtype.UUID,
	components []cdx.Component,
) error {
	for i := range components {
		comp := &components[i]
		major, minor, patch := parseSemver(comp.Version)

		compID, err := q.InsertComponent(ctx, repository.InsertComponentParams{
			SbomID:       sbomID,
			ParentID:     parentID,
			BomRef:       textOrNull(comp.BOMRef),
			Type:         string(comp.Type),
			Name:         comp.Name,
			GroupName:    textOrNull(comp.Group),
			Version:      textOrNull(comp.Version),
			VersionMajor: intOrNull(major),
			VersionMinor: intOrNull(minor),
			VersionPatch: intOrNull(patch),
			Purl:         textOrNull(comp.PackageURL),
			Cpe:          textOrNull(comp.CPE),
			Description:  textOrNull(comp.Description),
			Scope:        textOrNull(string(comp.Scope)),
			Publisher:    textOrNull(comp.Publisher),
			Copyright:    textOrNull(comp.Copyright),
		})
		if err != nil {
			return fmt.Errorf("inserting component %q: %w", comp.Name, err)
		}

		if err := s.insertComponentHashes(ctx, q, compID, comp.Hashes); err != nil {
			return err
		}

		if err := s.insertComponentLicenses(ctx, q, compID, comp.Licenses); err != nil {
			return err
		}

		if err := s.insertComponentExtRefs(ctx, q, compID, comp.ExternalReferences); err != nil {
			return err
		}

		// Recurse into nested components.
		if comp.Components != nil {
			if err := s.insertComponents(ctx, q, sbomID, compID, *comp.Components); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *sbomService) insertComponentHashes(
	ctx context.Context,
	q *repository.Queries,
	compID pgtype.UUID,
	hashes *[]cdx.Hash,
) error {
	if hashes == nil {
		return nil
	}
	for _, h := range *hashes {
		if err := q.InsertComponentHash(ctx, repository.InsertComponentHashParams{
			ComponentID: compID,
			Algorithm:   string(h.Algorithm),
			Value:       h.Value,
		}); err != nil {
			return fmt.Errorf("inserting hash: %w", err)
		}
	}
	return nil
}

func (s *sbomService) insertComponentLicenses(
	ctx context.Context,
	q *repository.Queries,
	compID pgtype.UUID,
	licenses *cdx.Licenses,
) error {
	if licenses == nil {
		return nil
	}
	for _, choice := range *licenses {
		if choice.License == nil {
			continue
		}
		lic := choice.License
		var licenseID pgtype.UUID
		var err error

		spdxID, displayName := NormalizeLicense(lic.ID, lic.Name)

		if spdxID != "" {
			// SPDX license (original or normalized from alias)
			licenseID, err = q.UpsertLicenseBySPDX(ctx, repository.UpsertLicenseBySPDXParams{
				SpdxID: pgtype.Text{String: spdxID, Valid: true},
				Name:   displayName,
				Url:    textOrNull(lic.URL),
			})
		} else {
			// Non-SPDX license
			licenseID, err = q.UpsertLicenseByName(ctx, repository.UpsertLicenseByNameParams{
				Name: displayName,
				Url:  textOrNull(lic.URL),
			})
		}
		if err != nil {
			return fmt.Errorf("upserting license: %w", err)
		}

		if err := q.InsertComponentLicense(ctx, repository.InsertComponentLicenseParams{
			ComponentID: compID,
			LicenseID:   licenseID,
		}); err != nil {
			return fmt.Errorf("inserting component license: %w", err)
		}
	}
	return nil
}

func (s *sbomService) insertComponentExtRefs(
	ctx context.Context,
	q *repository.Queries,
	compID pgtype.UUID,
	refs *[]cdx.ExternalReference,
) error {
	if refs == nil {
		return nil
	}
	for _, ref := range *refs {
		if err := q.InsertExternalReference(ctx, repository.InsertExternalReferenceParams{
			ComponentID: compID,
			Type:        string(ref.Type),
			Url:         ref.URL,
			Comment:     textOrNull(ref.Comment),
		}); err != nil {
			return fmt.Errorf("inserting external reference: %w", err)
		}
	}
	return nil
}

func (s *sbomService) insertDependencies(
	ctx context.Context,
	q *repository.Queries,
	sbomID pgtype.UUID,
	deps []cdx.Dependency,
) error {
	for _, dep := range deps {
		if dep.Dependencies == nil {
			continue
		}
		for _, target := range *dep.Dependencies {
			if err := q.InsertDependency(ctx, repository.InsertDependencyParams{
				SbomID:    sbomID,
				Ref:       dep.Ref,
				DependsOn: target,
			}); err != nil {
				return fmt.Errorf("inserting dependency: %w", err)
			}
		}
	}
	return nil
}

// ociVersionKeys are property names that contain a human-readable image version.
var ociVersionKeys = []string{
	"syft:image:labels:org.opencontainers.image.version",
	"aquasecurity:trivy:Labels:org.opencontainers.image.version",
	"syft:image:labels:org.label-schema.version", // legacy
}

// ociArchKeys are property names that contain the image architecture.
var ociArchKeys = []string{
	"syft:image:labels:org.opencontainers.image.architecture",
}

// ociBuildDateKeys are property names that contain the image build date.
var ociBuildDateKeys = []string{
	"syft:image:labels:org.opencontainers.image.created",
	"syft:image:labels:org.label-schema.build-date", // legacy
}

// isMoreSpecific reports whether candidate is a patch-level refinement of base:
// same major.minor, base has no patch component, candidate has a valid patch.
func isMoreSpecific(candidate, base string) bool {
	cMaj, cMin, cPatch := parseSemver(candidate)
	bMaj, bMin, bPatch := parseSemver(base)
	return cMaj >= 0 && cMin >= 0 && cPatch >= 0 &&
		bMaj == cMaj && bMin == cMin &&
		bPatch < 0
}

// resolveSubjectVersion returns the human-readable version for an SBOM's subject.
// params.Version takes precedence; then metadata.component.version when it is not
// a digest; then well-known OCI label properties emitted by Syft and Trivy.
func resolveSubjectVersion(bom *cdx.BOM, params IngestParams) pgtype.Text {
	if params.Version != "" {
		mc := bom.Metadata.Component
		if mc != nil && mc.Version != "" && !strings.HasPrefix(mc.Version, "sha256:") {
			if isMoreSpecific(mc.Version, params.Version) {
				return pgtype.Text{String: mc.Version, Valid: true}
			}
		}
		return pgtype.Text{String: params.Version, Valid: true}
	}

	mc := bom.Metadata.Component

	// Use the explicit version if it exists and isn't a digest.
	if mc.Version != "" && !strings.HasPrefix(mc.Version, "sha256:") {
		return pgtype.Text{String: mc.Version, Valid: true}
	}

	// Search component properties, then top-level metadata properties.
	for _, props := range [][]cdx.Property{propertySlice(mc.Properties), propertySlice(bom.Metadata.Properties)} {
		for _, p := range props {
			for _, key := range ociVersionKeys {
				if p.Name == key && p.Value != "" {
					return pgtype.Text{String: p.Value, Valid: true}
				}
			}
		}
	}

	return pgtype.Text{}
}

// resolveArchitecture returns the image architecture from params or BOM properties.
func resolveArchitecture(bom *cdx.BOM, params IngestParams) string {
	if params.Architecture != "" {
		return params.Architecture
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return ""
	}
	mc := bom.Metadata.Component
	for _, props := range [][]cdx.Property{propertySlice(mc.Properties), propertySlice(bom.Metadata.Properties)} {
		for _, p := range props {
			for _, key := range ociArchKeys {
				if p.Name == key && p.Value != "" {
					return p.Value
				}
			}
		}
	}
	return ""
}

// resolveBuildDate returns the image build date from params or BOM properties.
func resolveBuildDate(bom *cdx.BOM, params IngestParams) string {
	if params.BuildDate != "" {
		return params.BuildDate
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return ""
	}
	mc := bom.Metadata.Component
	for _, props := range [][]cdx.Property{propertySlice(mc.Properties), propertySlice(bom.Metadata.Properties)} {
		for _, p := range props {
			for _, key := range ociBuildDateKeys {
				if p.Name == key && p.Value != "" {
					return p.Value
				}
			}
		}
	}
	return ""
}

// propertySlice safely dereferences a *[]cdx.Property.
func propertySlice(p *[]cdx.Property) []cdx.Property {
	if p == nil {
		return nil
	}
	return *p
}

// parseSemver extracts major, minor, patch from a version string.
// Returns -1 for any part that cannot be parsed.
func parseSemver(version string) (major, minor, patch int) {
	major, minor, patch = -1, -1, -1
	if version == "" {
		return
	}
	// Strip leading 'v' if present.
	version = strings.TrimPrefix(version, "v")
	parts := strings.SplitN(version, ".", 3)

	if len(parts) >= 1 {
		if v, err := strconv.Atoi(parts[0]); err == nil {
			major = v
		}
	}
	if len(parts) >= 2 {
		if v, err := strconv.Atoi(parts[1]); err == nil {
			minor = v
		}
	}
	if len(parts) >= 3 {
		// Strip pre-release suffix (e.g., "1-beta" → "1").
		patchStr := strings.SplitN(parts[2], "-", 2)[0]
		patchStr = strings.SplitN(patchStr, "+", 2)[0]
		if v, err := strconv.Atoi(patchStr); err == nil {
			patch = v
		}
	}
	return
}

// textOrNull returns a valid pgtype.Text if s is non-empty, null otherwise.
func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// boolOrNull returns a valid pgtype.Bool when b is true, null otherwise.
// This allows the SQL query to skip the filter when the value is not set.
func boolOrNull(b bool) pgtype.Bool {
	if !b {
		return pgtype.Bool{}
	}
	return pgtype.Bool{Bool: true, Valid: true}
}

// intOrNull returns a valid pgtype.Int4 if v >= 0, null otherwise.
func intOrNull(v int) pgtype.Int4 {
	if v < 0 {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: int32(v), Valid: true} //nolint:gosec // semver parts are always small
}

// extractDigestFromBOM returns the image digest from a BOM's metadata component,
// mirroring the extraction logic in resolveArtifact.
func extractDigestFromBOM(bom *cdx.BOM) string {
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return ""
	}
	mc := bom.Metadata.Component
	if idx := strings.Index(mc.Name, "@sha256:"); idx != -1 {
		return mc.Name[idx+1:]
	}
	if strings.HasPrefix(mc.Version, "sha256:") {
		return mc.Version
	}
	return ""
}

// validateContainerDigest checks that container SBOMs reference a single image
// manifest, not a manifest list. Skipped if no validator is configured.
func (s *sbomService) validateContainerDigest(ctx context.Context, bom *cdx.BOM) error {
	if s.digestValidator == nil {
		return nil
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return nil
	}
	mc := bom.Metadata.Component
	if mc.Type != cdx.ComponentTypeContainer {
		return nil
	}

	// Extract name and digest the same way resolveArtifact does.
	name := mc.Name
	var digest string
	if idx := strings.Index(name, "@sha256:"); idx != -1 {
		digest = name[idx+1:]
		name = name[:idx]
	}
	if digest == "" && strings.HasPrefix(mc.Version, "sha256:") {
		digest = mc.Version
	}
	if digest == "" {
		return nil
	}

	if err := s.digestValidator.ValidateDigest(ctx, name, digest); err != nil {
		return &ValidationError{Message: err.Error()}
	}
	return nil
}

// Ensure *Queries satisfies the SBOMRepository and ArtifactRepository interfaces.
var _ repository.SBOMRepository = (*repository.Queries)(nil)
var _ repository.ArtifactRepository = (*repository.Queries)(nil)

// Ensure pgx.Tx satisfies DBTX for WithTx usage.
var _ repository.DBTX = (pgx.Tx)(nil)
