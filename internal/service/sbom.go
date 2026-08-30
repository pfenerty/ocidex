// Package service contains business logic interfaces and implementations.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/repository"
)

// dbPool is satisfied by *pgxpool.Pool. Extracted to allow unit-test injection.
type dbPool interface {
	repository.DBTX
	Begin(ctx context.Context) (pgx.Tx, error)
}

// copyFromer is the subset of pgx.Tx used for bulk COPY inserts during
// ingestion. Extracted to allow unit-test injection.
type copyFromer interface {
	CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)
}

// IngestParams carries supplemental metadata for SBOM ingestion.
// Fields take precedence over BOM-extracted values when set.
type IngestParams struct {
	Version      string      // image tag / subject version
	Architecture string      // e.g. "amd64"
	BuildDate    string      // RFC3339 or date string
	SourceID     pgtype.UUID // ingest channel the SBOM arrived through; required (ADR-039)
	IndexDigest  string      // multi-arch index this child was scanned from; empty for single-arch

	// Caller-declared subject identity (ADR-040). A `syft dir:` BOM describes
	// the scratch directory it walked, so a non-container uploader must state
	// what the SBOM is actually about. Applied field by field over
	// bom.Metadata.Component, so a caller can correct only what is wrong.
	SubjectType  string // CycloneDX component type, e.g. "application"
	SubjectName  string // e.g. "ocidex"
	SubjectGroup string // e.g. "github.com/pfenerty"
	SubjectPurl  string // e.g. "pkg:golang/github.com/pfenerty/ocidex@v1.2.3"
	Digest       string // sha256 of the artifact *file*, not of the SBOM
}

// SBOMService defines the business logic for SBOM ingestion and management.
type SBOMService interface {
	Ingest(ctx context.Context, bom *cdx.BOM, rawJSON []byte, params IngestParams) (pgtype.UUID, error)
	DeleteSBOM(ctx context.Context, id pgtype.UUID) error
	DeleteArtifact(ctx context.Context, id pgtype.UUID) error
	ListDigestsBySource(ctx context.Context, sourceID string) (map[string]bool, error)
	// GetSBOMNamespaceID returns the namespace_id for the given SBOM.
	// Returns a zero UUID (with Valid=false) when the SBOM has no registry association.
	// Returns ErrNotFound if no SBOM with that ID exists.
	GetSBOMNamespaceID(ctx context.Context, id pgtype.UUID) (pgtype.UUID, error)
	// GetArtifactNamespaceID returns one namespace the artifact hangs from —
	// the authorization anchor a capability check asks its question of.
	// Returns a zero UUID (with Valid=false) when the artifact hangs from none.
	// Returns ErrNotFound if no artifact with that ID exists.
	GetArtifactNamespaceID(ctx context.Context, id pgtype.UUID) (pgtype.UUID, error)
}

// DigestValidator validates that a container image digest points to a single
// image manifest rather than a manifest list (image index).
type DigestValidator interface {
	ValidateDigest(ctx context.Context, imageName, digest string) error
}

type sbomService struct {
	pool            dbPool
	publisher       event.Publisher
	digestValidator DigestValidator
}

// NewSBOMService creates a new SBOMService. The publisher and validator
// are optional; if nil, the corresponding functionality is skipped.
func NewSBOMService(pool dbPool, publisher event.Publisher, validator DigestValidator) SBOMService {
	return &sbomService{pool: pool, publisher: publisher, digestValidator: validator}
}

// artifactInfo holds the resolved artifact identity extracted from a BOM's metadata.
type artifactInfo struct {
	artifactID     pgtype.UUID
	subjectVersion pgtype.Text
	digest         pgtype.Text
	subjectType    string
}

// subjectIdentity is the effective identity of an SBOM's subject: caller-declared
// values layered over whatever bom.Metadata.Component carries.
type subjectIdentity struct {
	typ   string
	name  string
	group string
	purl  string
	cpe   string
}

// resolveSubjectIdentity applies IngestParams overrides over the BOM's subject
// component, field by field. Params win, per the IngestParams contract, so an
// uploader can correct just the name and purl of a `syft dir:` BOM without
// having to restate everything else (ADR-040).
func resolveSubjectIdentity(bom *cdx.BOM, params IngestParams) subjectIdentity {
	var s subjectIdentity
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		mc := bom.Metadata.Component
		s = subjectIdentity{
			typ:   string(mc.Type),
			name:  mc.Name,
			group: mc.Group,
			purl:  mc.PackageURL,
			cpe:   mc.CPE,
		}
	}
	if params.SubjectType != "" {
		s.typ = params.SubjectType
	}
	if params.SubjectName != "" {
		s.name = params.SubjectName
	}
	if params.SubjectGroup != "" {
		s.group = params.SubjectGroup
	}
	if params.SubjectPurl != "" {
		s.purl = params.SubjectPurl
	}
	return s
}

// resolveArtifact extracts artifact identity from the BOM metadata and upserts
// the artifact row. It returns the artifact ID, subject version, and image digest.
func resolveArtifact(ctx context.Context, q *repository.Queries, bom *cdx.BOM, params IngestParams) (artifactInfo, error) {
	// A BOM with no subject component and no declared identity yields no
	// artifact, as before.
	hasSubjectComponent := bom.Metadata != nil && bom.Metadata.Component != nil
	if !hasSubjectComponent && params.SubjectName == "" {
		return artifactInfo{}, nil
	}

	subj := resolveSubjectIdentity(bom, params)
	isContainer := subj.typ == string(cdx.ComponentTypeContainer)

	// A declared digest wins: for an upload it is the sha256 of the artifact
	// file, which the BOM has no way to carry (ADR-040).
	var digest pgtype.Text
	if params.Digest != "" {
		digest = pgtype.Text{String: params.Digest, Valid: true}
	}

	// Normalize container image names: strip digest suffix so that
	// "docker.io/ubuntu@sha256:abc..." and "docker.io/ubuntu" resolve
	// to the same artifact. Capture the digest for indexing.
	name := subj.name
	if isContainer {
		if idx := strings.Index(name, "@sha256:"); idx != -1 {
			if !digest.Valid {
				digest = pgtype.Text{String: name[idx+1:], Valid: true}
			}
			name = name[:idx]
		}
	}

	// Also check metadata.component.version for digest (e.g. "sha256:abc...").
	if !digest.Valid && hasSubjectComponent {
		if v := bom.Metadata.Component.Version; v != "" && strings.HasPrefix(v, "sha256:") {
			digest = pgtype.Text{String: v, Valid: true}
		}
	}

	// Container SBOMs must include a digest for reproducibility and enrichment.
	if isContainer && !digest.Valid {
		return artifactInfo{}, &ValidationError{
			Message: fmt.Sprintf("container SBOM for %q missing digest: include digest in component name (@sha256:...) or version", name),
		}
	}

	artifactID, err := q.UpsertArtifact(ctx, repository.UpsertArtifactParams{
		Type:      subj.typ,
		Name:      name,
		GroupName: textOrNull(subj.group),
		Purl:      textOrNull(subj.purl),
		Cpe:       textOrNull(subj.cpe),
	})
	if err != nil {
		return artifactInfo{}, fmt.Errorf("upserting artifact: %w", err)
	}

	return artifactInfo{
		artifactID:     artifactID,
		subjectVersion: resolveSubjectVersion(bom, params),
		digest:         digest,
		subjectType:    subj.typ,
	}, nil
}

// Ingest decomposes a CycloneDX BOM and persists it in a single transaction.
func (s *sbomService) Ingest(ctx context.Context, bom *cdx.BOM, rawJSON []byte, params IngestParams) (pgtype.UUID, error) {
	// An SBOM cannot exist unowned, so resolve the owner before doing any work.
	namespaceID, err := s.resolveIngestNamespace(ctx, params.SourceID)
	if err != nil {
		return pgtype.UUID{}, err
	}

	// Validate container digests before starting the transaction.
	// This makes a network call to the registry, so it runs outside the tx.
	if err := s.validateContainerDigest(ctx, bom); err != nil {
		return pgtype.UUID{}, err
	}

	// Idempotency check: if we already have an SBOM for this digest, skip ingestion.
	// A declared digest wins — an upload's digest lives nowhere in the BOM, and
	// missing it here would defer duplicate detection to the UNIQUE index, i.e.
	// until after a full transaction and component decomposition (ADR-040).
	if digest := resolveIngestDigest(bom, params); digest != "" {
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
	flavor := DetectFlavor(bom, info.subjectVersion.String)

	// Mandatory validation for container SBOMs.
	if err := validateContainerRequired(bom, info, arch, bd); err != nil {
		return pgtype.UUID{}, err
	}

	// Mandatory validation for non-container (uploaded) SBOMs.
	if err := validateUploadRequired(info, params); err != nil {
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
		NamespaceID:    namespaceID,
		SourceID:       params.SourceID,
		Flavor:         pgtype.Text{String: flavor, Valid: true},
		IndexDigest:    pgtype.Text{String: params.IndexDigest, Valid: params.IndexDigest != ""},
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("inserting sbom: %w", err)
	}

	slog.InfoContext(ctx, "persisting sbom",
		"sbom_id", sbomRow.ID,
		"spec_version", sbomRow.SpecVersion,
		"artifact_id", info.artifactID,
	)

	if err := linkArtifactNamespace(ctx, q, info.artifactID, namespaceID); err != nil {
		return pgtype.UUID{}, err
	}

	if err := s.insertBOMContent(ctx, tx, q, sbomRow.ID, bom, info.subjectVersion.String, flavor); err != nil {
		return pgtype.UUID{}, err
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
			Architecture:   arch,
			BuildDate:      bd,
		})
	}

	return sbomRow.ID, nil
}

// validateContainerRequired returns a ValidationError if a container SBOM is missing
// mandatory metadata fields.
func validateContainerRequired(bom *cdx.BOM, info artifactInfo, arch, bd string) error {
	if bom.Metadata == nil || bom.Metadata.Component == nil ||
		bom.Metadata.Component.Type != cdx.ComponentTypeContainer {
		return nil
	}
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
		return &ValidationError{
			Message: fmt.Sprintf("container SBOM missing required metadata: %s", strings.Join(missing, ", ")),
		}
	}
	return nil
}

// validateUploadRequired returns a ValidationError if a non-container SBOM is
// missing the subject identity its caller must declare (ADR-040).
//
// Subject type is the gate rather than the source kind: the registry scanner
// produces container subjects exclusively, so a non-container subject can only
// have arrived through the upload path. Type and name are not checked here —
// without them no artifact is resolved at all, and info.artifactID is invalid.
// resolveIngestNamespace derives the tenancy anchor for an ingest from the
// source it arrived through.
//
// The namespace is deliberately not a second input. Deriving it from exactly
// one place means a caller cannot name a source in one namespace and have the
// row land in another, and it retires the assumption — previously duplicated at
// every call site — that a registry's id doubles as its namespace id. That
// holds only for a registry that created its own namespace; when the operator
// creates a registry inside an existing namespace, source id and namespace id
// differ (ADR-039, `CreateRegistry` in db/queries/registry.sql).
//
// A missing or unknown source is a ValidationError, which the API layer renders
// as 400. Since 00054 the column is NOT NULL, so there is no unowned fallback.
func (s *sbomService) resolveIngestNamespace(ctx context.Context, sourceID pgtype.UUID) (pgtype.UUID, error) {
	if !sourceID.Valid {
		return pgtype.UUID{}, &ValidationError{
			Message: "sbom ingest requires a source; pass ?source=<uuid|namespace/name> so the SBOM lands in a namespace that owns it",
		}
	}
	src, err := repository.New(s.pool).GetSource(ctx, sourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return pgtype.UUID{}, &ValidationError{Message: "ingest source not found"}
		}
		return pgtype.UUID{}, fmt.Errorf("resolving ingest source: %w", err)
	}
	return src.NamespaceID, nil
}

func validateUploadRequired(info artifactInfo, params IngestParams) error {
	if !info.artifactID.Valid || info.subjectType == "" ||
		info.subjectType == string(cdx.ComponentTypeContainer) {
		return nil
	}
	var missing []string
	// Type and name must be *declared*, not merely resolved. A `syft dir:` BOM
	// always supplies both — describing the scratch directory it walked — so
	// accepting the BOM's values is how an artifact ends up named `.sbom-bins`.
	// Requiring the declaration is the whole point of ADR-040.
	if params.SubjectType == "" {
		missing = append(missing, "subject_type")
	}
	if params.SubjectName == "" {
		missing = append(missing, "subject_name")
	}
	if !info.subjectVersion.Valid || info.subjectVersion.String == "" {
		missing = append(missing, "subject_version")
	}
	if !info.digest.Valid || info.digest.String == "" {
		missing = append(missing, "digest")
	}
	if len(missing) > 0 {
		return &ValidationError{
			Message: fmt.Sprintf(
				"non-container SBOM missing required subject identity: %s; declare it at upload (digest is the sha256 of the artifact file)",
				strings.Join(missing, ", "),
			),
		}
	}
	return nil
}

// insertBOMContent inserts components and dependencies for an SBOM within a transaction.
func (s *sbomService) insertBOMContent(ctx context.Context, tx copyFromer, q *repository.Queries, sbomID pgtype.UUID, bom *cdx.BOM, subjectVersion, flavor string) error {
	mainModule := extractMainModulePath(bom)
	if bom.Components != nil {
		if err := s.insertComponentsBatch(ctx, tx, q, sbomID, *bom.Components, mainModule, subjectVersion, flavor); err != nil {
			return err
		}
	}
	if bom.Dependencies != nil {
		if err := s.insertDependencies(ctx, q, sbomID, *bom.Dependencies); err != nil {
			return err
		}
	}
	return nil
}

// linkArtifactNamespace records the artifact→namespace relationship in the junction table.
func linkArtifactNamespace(ctx context.Context, q *repository.Queries, artifactID, namespaceID pgtype.UUID) error {
	if !artifactID.Valid || !namespaceID.Valid {
		return nil
	}
	if err := q.UpsertArtifactNamespace(ctx, repository.UpsertArtifactNamespaceParams{
		ArtifactID:  artifactID,
		NamespaceID: namespaceID,
	}); err != nil {
		return fmt.Errorf("linking artifact to namespace: %w", err)
	}
	return nil
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

// ListDigestsBySource returns the set of SBOM digests already ingested through
// a source, so a rescan can skip them.
func (s *sbomService) ListDigestsBySource(ctx context.Context, sourceID string) (map[string]bool, error) {
	var srcUUID pgtype.UUID
	if err := srcUUID.Scan(sourceID); err != nil {
		return nil, fmt.Errorf("parsing source ID: %w", err)
	}
	q := repository.New(s.pool)
	rows, err := q.ListDigestsBySource(ctx, srcUUID)
	if err != nil {
		return nil, fmt.Errorf("listing digests: %w", err)
	}
	out := make(map[string]bool, len(rows))
	for _, d := range rows {
		if d.Valid {
			out[d.String] = true
		}
	}
	return out, nil
}

func (s *sbomService) GetSBOMNamespaceID(ctx context.Context, id pgtype.UUID) (pgtype.UUID, error) {
	q := repository.New(s.pool)
	row, err := q.GetSBOM(ctx, id)
	if err != nil {
		return pgtype.UUID{}, ErrNotFound
	}
	return row.NamespaceID, nil
}

func (s *sbomService) GetArtifactNamespaceID(ctx context.Context, id pgtype.UUID) (pgtype.UUID, error) {
	q := repository.New(s.pool)
	if _, err := q.GetArtifact(ctx, id); err != nil {
		return pgtype.UUID{}, ErrNotFound
	}
	namespaceID, err := q.GetArtifactNamespaceID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return pgtype.UUID{}, nil
	}
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("looking up artifact namespace: %w", err)
	}
	return namespaceID, nil
}

// Ensure *Queries satisfies the SBOMRepository and ArtifactRepository interfaces.
var _ repository.SBOMRepository = (*repository.Queries)(nil)

var _ repository.ArtifactRepository = (*repository.Queries)(nil)

// Ensure pgx.Tx satisfies DBTX for WithTx usage.
var _ repository.DBTX = (pgx.Tx)(nil)
