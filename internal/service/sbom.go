// Package service contains business logic interfaces and implementations.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/repository"
)

// SBOMService defines the business logic for SBOM ingestion and management.
type SBOMService interface {
	Ingest(ctx context.Context, bom *cdx.BOM, rawJSON []byte) (pgtype.UUID, error)
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
	dispatcher      *enrichment.Dispatcher
	digestValidator DigestValidator
}

// NewSBOMService creates a new SBOMService. The dispatcher and validator
// are optional; if nil, the corresponding functionality is skipped.
func NewSBOMService(pool *pgxpool.Pool, dispatcher *enrichment.Dispatcher, validator DigestValidator) SBOMService {
	return &sbomService{pool: pool, dispatcher: dispatcher, digestValidator: validator}
}

// artifactInfo holds the resolved artifact identity extracted from a BOM's metadata.
type artifactInfo struct {
	artifactID     pgtype.UUID
	subjectVersion pgtype.Text
	digest         pgtype.Text
}

// resolveArtifact extracts artifact identity from the BOM metadata and upserts
// the artifact row. It returns the artifact ID, subject version, and image digest.
func resolveArtifact(ctx context.Context, q *repository.Queries, bom *cdx.BOM) (artifactInfo, error) {
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
		subjectVersion: resolveSubjectVersion(bom),
		digest:         digest,
	}, nil
}

// Ingest decomposes a CycloneDX BOM and persists it in a single transaction.
func (s *sbomService) Ingest(ctx context.Context, bom *cdx.BOM, rawJSON []byte) (pgtype.UUID, error) {
	// Validate container digests before starting the transaction.
	// This makes a network call to the registry, so it runs outside the tx.
	if err := s.validateContainerDigest(ctx, bom); err != nil {
		return pgtype.UUID{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on committed tx is a no-op

	q := repository.New(tx)

	info, err := resolveArtifact(ctx, q, bom)
	if err != nil {
		return pgtype.UUID{}, err
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

	// Submit for async enrichment after successful commit.
	if s.dispatcher != nil && sbomRow.ID.Valid {
		s.dispatcher.Submit(enrichment.SubjectRef{
			SBOMId:         sbomRow.ID,
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
}

// resolveSubjectVersion returns the human-readable version for an SBOM's subject.
// It prefers metadata.component.version when it is not a digest, then falls back
// to well-known OCI label properties emitted by Syft and Trivy.
func resolveSubjectVersion(bom *cdx.BOM) pgtype.Text {
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

// intOrNull returns a valid pgtype.Int4 if v >= 0, null otherwise.
func intOrNull(v int) pgtype.Int4 {
	if v < 0 {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: int32(v), Valid: true} //nolint:gosec // semver parts are always small
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
