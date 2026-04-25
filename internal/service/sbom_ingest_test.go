package service

import (
	"context"
	"errors"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/repository" //nolint:depguard
)

// ---- fake infrastructure ----

// fakeRow implements pgx.Row.
type fakeRow struct{ scanFn func(dest ...any) error }

func (r *fakeRow) Scan(dest ...any) error { return r.scanFn(dest...) }

// noRowsRow returns pgx.ErrNoRows, simulating a missing DB record.
type noRowsRow struct{}

func (noRowsRow) Scan(...any) error { return pgx.ErrNoRows }

// fakeDB implements dbPool. Configure per-test via function fields.
// Nil function fields fall back to a safe no-op.
type fakeDB struct {
	queryRowFn  func(ctx context.Context, sql string, args ...any) pgx.Row
	execFn      func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	queryFn     func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	beginFn     func(ctx context.Context) (pgx.Tx, error)
	beginCalled bool
}

func (db *fakeDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if db.queryRowFn != nil {
		return db.queryRowFn(ctx, sql, args...)
	}
	return noRowsRow{}
}

func (db *fakeDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if db.execFn != nil {
		return db.execFn(ctx, sql, args...)
	}
	return pgconn.CommandTag{}, nil
}

func (db *fakeDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if db.queryFn != nil {
		return db.queryFn(ctx, sql, args...)
	}
	return nil, nil
}

func (db *fakeDB) Begin(ctx context.Context) (pgx.Tx, error) {
	db.beginCalled = true
	if db.beginFn != nil {
		return db.beginFn(ctx)
	}
	return nil, errors.New("fakeDB: beginFn not configured")
}

// fakeTx implements pgx.Tx. Only DBTX methods + Commit/Rollback are functional;
// the rest panic to catch unexpected calls during tests.
type fakeTx struct {
	fakeDB
	commitFn   func(ctx context.Context) error
	rollbackFn func(ctx context.Context) error
}

func (tx *fakeTx) Commit(ctx context.Context) error {
	if tx.commitFn != nil {
		return tx.commitFn(ctx)
	}
	return nil
}

func (tx *fakeTx) Rollback(ctx context.Context) error {
	if tx.rollbackFn != nil {
		return tx.rollbackFn(ctx)
	}
	return nil
}

func (tx *fakeTx) Begin(ctx context.Context) (pgx.Tx, error) {
	panic("fakeTx: nested Begin not expected")
}

func (tx *fakeTx) CopyFrom(_ context.Context, _ pgx.Identifier, _ []string, _ pgx.CopyFromSource) (int64, error) {
	panic("fakeTx: CopyFrom not expected")
}

func (tx *fakeTx) SendBatch(_ context.Context, _ *pgx.Batch) pgx.BatchResults {
	panic("fakeTx: SendBatch not expected")
}

func (tx *fakeTx) LargeObjects() pgx.LargeObjects { panic("fakeTx: LargeObjects not expected") }

func (tx *fakeTx) Prepare(_ context.Context, _, _ string) (*pgconn.StatementDescription, error) {
	panic("fakeTx: Prepare not expected")
}

func (tx *fakeTx) Conn() *pgx.Conn { return nil }

// fakePublisher records published events.
type fakePublisher struct{ events []event.Type }

func (p *fakePublisher) Publish(_ context.Context, t event.Type, _ any) {
	p.events = append(p.events, t)
}

// ---- helpers ----

func newUUID(t *testing.T) pgtype.UUID {
	t.Helper()
	var id pgtype.UUID
	_ = id.Scan("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
	return id
}

func newUUID2(t *testing.T) pgtype.UUID {
	t.Helper()
	var id pgtype.UUID
	_ = id.Scan("b1ffcd00-0d1c-4fa9-cc7e-7cc0ce491b22")
	return id
}

// containerBOM builds a minimal CycloneDX container BOM with a digest in the
// component name.
func containerBOM(name, digest, version string) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			Type:    cdx.ComponentTypeContainer,
			Name:    name + "@" + digest,
			Version: version,
		},
	}
	return bom
}

// fullContainerBOM adds a component with a license and a dependency edge to the
// given BOM so we can exercise insertBOMContent paths.
func fullContainerBOM(name, digest string) *cdx.BOM {
	bom := cdx.NewBOM()
	compRef := "pkg:apk/alpine-baselayout@3.4.3-r2"
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			Type:    cdx.ComponentTypeContainer,
			Name:    name + "@" + digest,
			Version: "3.18.4",
		},
	}
	bom.Components = &[]cdx.Component{
		{
			BOMRef:     compRef,
			Type:       cdx.ComponentTypeLibrary,
			Name:       "alpine-baselayout",
			Version:    "3.4.3-r2",
			PackageURL: compRef,
			Licenses: &cdx.Licenses{
				{License: &cdx.License{ID: "GPL-2.0-only", Name: "GNU General Public License v2.0 only"}},
			},
		},
	}
	bom.Dependencies = &[]cdx.Dependency{
		{Ref: name + "@" + digest, Dependencies: &[]string{compRef}},
	}
	return bom
}

// ---- tests ----

// TestIngest_IdempotencyOnDuplicateDigest verifies that when a BOM's digest is
// already known, Ingest returns the existing SBOM ID without opening a transaction.
func TestIngest_IdempotencyOnDuplicateDigest(t *testing.T) {
	is := is.New(t)
	existingID := newUUID(t)

	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				*(dest[0].(*pgtype.UUID)) = existingID
				return nil
			}}
		},
	}

	svc := NewSBOMService(db, nil, nil)
	bom := containerBOM("docker.io/ubuntu", "sha256:abc123def456", "22.04")

	id, err := svc.Ingest(context.Background(), bom, []byte("{}"),
		IngestParams{Version: "22.04", Architecture: "amd64", BuildDate: "2024-01-01"})

	is.NoErr(err)
	is.Equal(id, existingID)
	is.True(!db.beginCalled) // no transaction opened for duplicate
}

// TestIngest_HappyPath exercises the full ingest path for a container SBOM with
// one component (with license) and one dependency edge.
func TestIngest_HappyPath_ContainerSBOM(t *testing.T) {
	is := is.New(t)
	artifactID := newUUID(t)
	sbomID := newUUID2(t)
	compID := newUUID(t)
	licenseID := newUUID(t)

	publisher := &fakePublisher{}

	// queryRowFn is called by: GetSBOMByDigest (returns no rows), UpsertArtifact,
	// InsertSBOM, InsertComponent, UpsertLicenseBySPDX (in tx via fakeTx).
	callCount := 0
	txQueryRow := func(_ context.Context, _ string, args ...any) pgx.Row {
		callCount++
		switch callCount {
		case 1: // UpsertArtifact
			return &fakeRow{scanFn: func(dest ...any) error {
				*(dest[0].(*pgtype.UUID)) = artifactID
				return nil
			}}
		case 2: // InsertSBOM — scans (ID UUID, SerialNumber text, SpecVersion string, Version int32, CreatedAt timestamptz)
			return &fakeRow{scanFn: func(dest ...any) error {
				*(dest[0].(*pgtype.UUID)) = sbomID
				*(dest[2].(*string)) = "1.4"
				return nil
			}}
		case 3: // InsertComponent
			return &fakeRow{scanFn: func(dest ...any) error {
				*(dest[0].(*pgtype.UUID)) = compID
				return nil
			}}
		case 4: // UpsertLicenseBySPDX
			return &fakeRow{scanFn: func(dest ...any) error {
				*(dest[0].(*pgtype.UUID)) = licenseID
				return nil
			}}
		default:
			return noRowsRow{}
		}
	}

	tx := &fakeTx{
		fakeDB: fakeDB{queryRowFn: txQueryRow},
	}

	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return noRowsRow{} // GetSBOMByDigest: no existing SBOM
		},
		beginFn: func(_ context.Context) (pgx.Tx, error) {
			return tx, nil
		},
	}

	svc := NewSBOMService(db, publisher, nil)
	bom := fullContainerBOM("docker.io/alpine", "sha256:deadbeef1234")

	id, err := svc.Ingest(context.Background(), bom, []byte("{}"),
		IngestParams{Version: "3.18.4", Architecture: "amd64", BuildDate: "2024-01-01"})

	is.NoErr(err)
	is.Equal(id, sbomID)
	is.True(db.beginCalled)
	is.Equal(len(publisher.events), 1)
	is.Equal(publisher.events[0], event.SBOMIngested)
}

// TestResolveArtifact_ContainerDigestInName verifies that a digest embedded in
// the component name is stripped from the artifact name and captured separately.
func TestResolveArtifact_ContainerDigestInName(t *testing.T) {
	is := is.New(t)
	artifactID := newUUID(t)

	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, args ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				*(dest[0].(*pgtype.UUID)) = artifactID
				return nil
			}}
		},
	}
	q := repository.New(db)

	bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
		Type:    cdx.ComponentTypeContainer,
		Name:    "docker.io/ubuntu@sha256:abc123",
		Version: "22.04",
	}}}

	info, err := resolveArtifact(context.Background(), q, bom, IngestParams{})
	is.NoErr(err)
	is.Equal(info.artifactID, artifactID)
	is.Equal(info.digest, pgtype.Text{String: "sha256:abc123", Valid: true})
}

// TestResolveArtifact_ContainerDigestInVersion verifies that a digest in
// mc.Version is captured as the artifact digest.
func TestResolveArtifact_ContainerDigestInVersion(t *testing.T) {
	is := is.New(t)
	artifactID := newUUID(t)

	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				*(dest[0].(*pgtype.UUID)) = artifactID
				return nil
			}}
		},
	}
	q := repository.New(db)

	bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
		Type:    cdx.ComponentTypeContainer,
		Name:    "docker.io/ubuntu",
		Version: "sha256:deadbeef",
	}}}

	info, err := resolveArtifact(context.Background(), q, bom, IngestParams{})
	is.NoErr(err)
	is.Equal(info.digest, pgtype.Text{String: "sha256:deadbeef", Valid: true})
}

// TestResolveArtifact_ContainerMissingDigest verifies that a container SBOM
// without a digest returns a ValidationError.
func TestResolveArtifact_ContainerMissingDigest(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{}
	q := repository.New(db)

	bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
		Type:    cdx.ComponentTypeContainer,
		Name:    "docker.io/ubuntu",
		Version: "22.04",
	}}}

	_, err := resolveArtifact(context.Background(), q, bom, IngestParams{})
	is.True(err != nil)
	var ve *ValidationError
	is.True(errors.As(err, &ve))
}

// TestResolveArtifact_NonContainer verifies that non-container components do not
// require a digest and resolve correctly.
func TestResolveArtifact_NonContainer(t *testing.T) {
	is := is.New(t)
	artifactID := newUUID(t)

	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				*(dest[0].(*pgtype.UUID)) = artifactID
				return nil
			}}
		},
	}
	q := repository.New(db)

	bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
		Type:    cdx.ComponentTypeLibrary,
		Name:    "some-lib",
		Version: "1.2.3",
	}}}

	info, err := resolveArtifact(context.Background(), q, bom, IngestParams{})
	is.NoErr(err)
	is.Equal(info.artifactID, artifactID)
	is.True(!info.digest.Valid) // no digest for non-container
}

// TestInsertComponentLicenses_SPDXPath verifies that a license with an SPDX ID
// routes through UpsertLicenseBySPDX (deduplication by SPDX key at DB level).
func TestInsertComponentLicenses_SPDXPath(t *testing.T) {
	is := is.New(t)
	licenseID := newUUID(t)
	compID := newUUID(t)

	var spdxCalled, nameCalled bool
	db := &fakeDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if contains(sql, "UpsertLicenseBySPDX") {
				spdxCalled = true
			} else {
				nameCalled = true
			}
			return &fakeRow{scanFn: func(dest ...any) error {
				*(dest[0].(*pgtype.UUID)) = licenseID
				return nil
			}}
		},
	}
	q := repository.New(db)
	svc := &sbomService{}

	licenses := &cdx.Licenses{{License: &cdx.License{ID: "MIT", Name: "MIT License"}}}
	err := svc.insertComponentLicenses(context.Background(), q, compID, licenses)
	is.NoErr(err)
	is.True(spdxCalled)
	is.True(!nameCalled)
}

// TestInsertComponentLicenses_NonSPDXPath verifies that a license without an
// SPDX ID routes through UpsertLicenseByName.
func TestInsertComponentLicenses_NonSPDXPath(t *testing.T) {
	is := is.New(t)
	licenseID := newUUID(t)
	compID := newUUID(t)

	var spdxCalled, nameCalled bool
	db := &fakeDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if contains(sql, "UpsertLicenseBySPDX") {
				spdxCalled = true
			} else {
				nameCalled = true
			}
			return &fakeRow{scanFn: func(dest ...any) error {
				*(dest[0].(*pgtype.UUID)) = licenseID
				return nil
			}}
		},
	}
	q := repository.New(db)
	svc := &sbomService{}

	licenses := &cdx.Licenses{{License: &cdx.License{Name: "Proprietary"}}}
	err := svc.insertComponentLicenses(context.Background(), q, compID, licenses)
	is.NoErr(err)
	is.True(!spdxCalled)
	is.True(nameCalled)
}

// TestInsertComponentLicenses_NilLicenses verifies that nil input is a no-op.
func TestInsertComponentLicenses_NilLicenses(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{}
	q := repository.New(db)
	svc := &sbomService{}

	err := svc.insertComponentLicenses(context.Background(), q, newUUID(t), nil)
	is.NoErr(err)
}

// TestInsertDependencies_GraphEdges verifies that all dependency edges from the
// BOM are written to the repository with correct ref/dependsOn values.
func TestInsertDependencies_GraphEdges(t *testing.T) {
	is := is.New(t)
	sbomID := newUUID(t)

	type edge struct{ ref, dep string }
	var recorded []edge

	db := &fakeDB{
		execFn: func(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
			if len(args) >= 3 {
				recorded = append(recorded, edge{
					ref: args[1].(string),
					dep: args[2].(string),
				})
			}
			return pgconn.CommandTag{}, nil
		},
	}
	q := repository.New(db)
	svc := &sbomService{}

	deps := []cdx.Dependency{
		{Ref: "A", Dependencies: &[]string{"B", "C"}},
		{Ref: "B", Dependencies: &[]string{"C"}},
	}
	err := svc.insertDependencies(context.Background(), q, sbomID, deps)
	is.NoErr(err)
	is.Equal(len(recorded), 3) // A→B, A→C, B→C
}

// TestInsertDependencies_NilDependencies verifies that a dependency with a nil
// dependencies list is skipped without error.
func TestInsertDependencies_NilDependencies(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{}
	q := repository.New(db)
	svc := &sbomService{}

	deps := []cdx.Dependency{{Ref: "A", Dependencies: nil}}
	err := svc.insertDependencies(context.Background(), q, newUUID(t), deps)
	is.NoErr(err)
}

// TestValidateContainerRequired_NonContainer verifies that non-container BOMs
// pass validation regardless of missing fields.
func TestValidateContainerRequired_NonContainer(t *testing.T) {
	is := is.New(t)
	bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
		Type: cdx.ComponentTypeLibrary,
	}}}
	err := validateContainerRequired(bom, artifactInfo{}, "", "")
	is.NoErr(err)
}

// TestValidateContainerRequired_MissingFields verifies that container BOMs
// missing required fields return a ValidationError naming the missing fields.
func TestValidateContainerRequired_MissingFields(t *testing.T) {
	is := is.New(t)
	bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
		Type: cdx.ComponentTypeContainer,
	}}}

	// All three missing.
	err := validateContainerRequired(bom, artifactInfo{}, "", "")
	var ve *ValidationError
	is.True(errors.As(err, &ve))
	is.True(contains(ve.Message, "subject_version"))
	is.True(contains(ve.Message, "architecture"))
	is.True(contains(ve.Message, "build_date"))

	// Only arch missing.
	info := artifactInfo{subjectVersion: pgtype.Text{String: "1.0", Valid: true}}
	err = validateContainerRequired(bom, info, "", "2024-01-01")
	is.True(errors.As(err, &ve))
	is.True(contains(ve.Message, "architecture"))
}

// TestValidateContainerRequired_AllPresent verifies that a fully populated
// container BOM passes validation.
func TestValidateContainerRequired_AllPresent(t *testing.T) {
	is := is.New(t)
	bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
		Type: cdx.ComponentTypeContainer,
	}}}
	info := artifactInfo{subjectVersion: pgtype.Text{String: "22.04", Valid: true}}
	err := validateContainerRequired(bom, info, "amd64", "2024-01-01")
	is.NoErr(err)
}

// TestExtractDigestFromBOM covers the three digest-extraction paths.
func TestExtractDigestFromBOM(t *testing.T) {
	tests := []struct {
		name string
		bom  *cdx.BOM
		want string
	}{
		{
			name: "digest in component name",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
				Name: "docker.io/ubuntu@sha256:abc123",
			}}},
			want: "sha256:abc123",
		},
		{
			name: "digest in component version",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
				Name:    "docker.io/ubuntu",
				Version: "sha256:deadbeef",
			}}},
			want: "sha256:deadbeef",
		},
		{
			name: "no digest",
			bom: &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
				Name:    "docker.io/ubuntu",
				Version: "22.04",
			}}},
			want: "",
		},
		{
			name: "nil metadata",
			bom:  &cdx.BOM{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(extractDigestFromBOM(tt.bom), tt.want)
		})
	}
}

// TestDeleteSBOM_NotFound verifies that deleting a non-existent SBOM returns ErrNotFound.
func TestDeleteSBOM_NotFound(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		execFn: func(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("DELETE 0"), nil
		},
	}
	svc := NewSBOMService(db, nil, nil)
	err := svc.DeleteSBOM(context.Background(), newUUID(t))
	is.True(errors.Is(err, ErrNotFound))
}

// TestDeleteSBOM_Success verifies that a successful deletion publishes a SBOMDeleted event.
func TestDeleteSBOM_Success(t *testing.T) {
	is := is.New(t)
	publisher := &fakePublisher{}
	db := &fakeDB{
		execFn: func(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("DELETE 1"), nil
		},
	}
	svc := NewSBOMService(db, publisher, nil)
	err := svc.DeleteSBOM(context.Background(), newUUID(t))
	is.NoErr(err)
	is.Equal(len(publisher.events), 1)
	is.Equal(publisher.events[0], event.SBOMDeleted)
}

// TestListDigestsByRegistry_InvalidUUID verifies that a malformed registry ID
// returns a parsing error.
func TestListDigestsByRegistry_InvalidUUID(t *testing.T) {
	is := is.New(t)
	svc := NewSBOMService(&fakeDB{}, nil, nil)
	_, err := svc.ListDigestsByRegistry(context.Background(), "not-a-uuid")
	is.True(err != nil)
}

// TestListDigestsByRegistry_Results verifies that digests returned by the
// repository are mapped into a boolean set, skipping null entries.
func TestListDigestsByRegistry_Results(t *testing.T) {
	is := is.New(t)

	digests := []pgtype.Text{
		{String: "sha256:aaa", Valid: true},
		{Valid: false}, // null — should be skipped
		{String: "sha256:bbb", Valid: true},
	}
	callIdx := 0
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return &fakeRows{rows: digests, idx: &callIdx}, nil
		},
	}
	svc := NewSBOMService(db, nil, nil)
	result, err := svc.ListDigestsByRegistry(context.Background(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
	is.NoErr(err)
	is.Equal(len(result), 2)
	is.True(result["sha256:aaa"])
	is.True(result["sha256:bbb"])
}

// fakeRows implements pgx.Rows for ListDigestsByRegistry.
type fakeRows struct {
	rows []pgtype.Text
	idx  *int
}

func (r *fakeRows) Next() bool { return *r.idx < len(r.rows) }
func (r *fakeRows) Scan(dest ...any) error {
	*(dest[0].(*pgtype.Text)) = r.rows[*r.idx]
	*r.idx++
	return nil
}
func (r *fakeRows) Err() error                                   { return nil }
func (r *fakeRows) Close()                                       {}
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Values() ([]any, error)                       { return nil, nil }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Conn() *pgx.Conn                              { return nil }

// TestDeleteArtifact_NotFound verifies that deleting a non-existent artifact returns ErrNotFound.
func TestDeleteArtifact_NotFound(t *testing.T) {
	is := is.New(t)
	execCount := 0
	tx := &fakeTx{
		fakeDB: fakeDB{
			execFn: func(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
				execCount++
				switch execCount {
				case 1: // DeleteSBOMsByArtifact
					return pgconn.NewCommandTag("DELETE 0"), nil
				default: // DeleteArtifact
					return pgconn.NewCommandTag("DELETE 0"), nil
				}
			},
		},
	}
	db := &fakeDB{
		beginFn: func(_ context.Context) (pgx.Tx, error) { return tx, nil },
	}
	svc := NewSBOMService(db, nil, nil)
	err := svc.DeleteArtifact(context.Background(), newUUID(t))
	is.True(errors.Is(err, ErrNotFound))
}

// TestDeleteArtifact_Success verifies full artifact deletion publishes an event and commits.
func TestDeleteArtifact_Success(t *testing.T) {
	is := is.New(t)
	publisher := &fakePublisher{}
	committed := false
	execCount := 0
	tx := &fakeTx{
		fakeDB: fakeDB{
			execFn: func(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
				execCount++
				switch execCount {
				case 1: // DeleteSBOMsByArtifact
					return pgconn.NewCommandTag("DELETE 3"), nil
				default: // DeleteArtifact
					return pgconn.NewCommandTag("DELETE 1"), nil
				}
			},
		},
		commitFn: func(_ context.Context) error {
			committed = true
			return nil
		},
	}
	db := &fakeDB{
		beginFn: func(_ context.Context) (pgx.Tx, error) { return tx, nil },
	}
	svc := NewSBOMService(db, publisher, nil)
	err := svc.DeleteArtifact(context.Background(), newUUID(t))
	is.NoErr(err)
	is.True(committed)
	is.Equal(len(publisher.events), 1)
	is.Equal(publisher.events[0], event.ArtifactDeleted)
}

// TestInsertComponentHashes verifies that component hashes are written for non-nil input.
func TestInsertComponentHashes(t *testing.T) {
	is := is.New(t)
	var recorded []string
	db := &fakeDB{
		execFn: func(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
			if len(args) >= 3 {
				recorded = append(recorded, args[2].(string))
			}
			return pgconn.CommandTag{}, nil
		},
	}
	q := repository.New(db)
	svc := &sbomService{}

	hashes := &[]cdx.Hash{
		{Algorithm: cdx.HashAlgoSHA256, Value: "abc123"},
		{Algorithm: cdx.HashAlgoMD5, Value: "def456"},
	}
	err := svc.insertComponentHashes(context.Background(), q, newUUID(t), hashes)
	is.NoErr(err)
	is.Equal(len(recorded), 2)
}

// TestInsertComponentHashes_Nil verifies that nil hashes is a no-op.
func TestInsertComponentHashes_Nil(t *testing.T) {
	is := is.New(t)
	svc := &sbomService{}
	err := svc.insertComponentHashes(context.Background(), repository.New(&fakeDB{}), newUUID(t), nil)
	is.NoErr(err)
}

// TestInsertComponentExtRefs verifies that external references are written for non-nil input.
func TestInsertComponentExtRefs(t *testing.T) {
	is := is.New(t)
	var recordedURLs []string
	db := &fakeDB{
		execFn: func(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
			if len(args) >= 3 {
				if url, ok := args[2].(string); ok {
					recordedURLs = append(recordedURLs, url)
				}
			}
			return pgconn.CommandTag{}, nil
		},
	}
	q := repository.New(db)
	svc := &sbomService{}

	refs := &[]cdx.ExternalReference{
		{Type: cdx.ERTypeWebsite, URL: "https://example.com"},
		{Type: cdx.ERTypeIssueTracker, URL: "https://issues.example.com"},
	}
	err := svc.insertComponentExtRefs(context.Background(), q, newUUID(t), refs)
	is.NoErr(err)
	is.Equal(len(recordedURLs), 2)
}

// TestInsertComponentExtRefs_Nil verifies that nil refs is a no-op.
func TestInsertComponentExtRefs_Nil(t *testing.T) {
	is := is.New(t)
	svc := &sbomService{}
	err := svc.insertComponentExtRefs(context.Background(), repository.New(&fakeDB{}), newUUID(t), nil)
	is.NoErr(err)
}

// TestValidateContainerDigest_NilValidator verifies that digest validation is
// skipped when no validator is configured.
func TestValidateContainerDigest_NilValidator(t *testing.T) {
	is := is.New(t)
	svc := &sbomService{digestValidator: nil}
	bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
		Type: cdx.ComponentTypeContainer,
		Name: "docker.io/ubuntu@sha256:abc123",
	}}}
	err := svc.validateContainerDigest(context.Background(), bom)
	is.NoErr(err)
}

// fakeDigestValidator implements DigestValidator for tests.
type fakeDigestValidator struct{ err error }

func (v *fakeDigestValidator) ValidateDigest(_ context.Context, _, _ string) error { return v.err }

// TestValidateContainerDigest_ValidatorSuccess verifies a passing validator allows ingest.
func TestValidateContainerDigest_ValidatorSuccess(t *testing.T) {
	is := is.New(t)
	svc := &sbomService{digestValidator: &fakeDigestValidator{err: nil}}
	bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
		Type:    cdx.ComponentTypeContainer,
		Name:    "docker.io/ubuntu@sha256:abc123",
		Version: "22.04",
	}}}
	err := svc.validateContainerDigest(context.Background(), bom)
	is.NoErr(err)
}

// TestValidateContainerDigest_ValidatorFailure verifies a failing validator returns ValidationError.
func TestValidateContainerDigest_ValidatorFailure(t *testing.T) {
	is := is.New(t)
	svc := &sbomService{digestValidator: &fakeDigestValidator{
		err: errors.New("manifest list not allowed"),
	}}
	bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
		Type: cdx.ComponentTypeContainer,
		Name: "docker.io/ubuntu@sha256:abc123",
	}}}
	err := svc.validateContainerDigest(context.Background(), bom)
	var ve *ValidationError
	is.True(errors.As(err, &ve))
}

// TestLinkArtifactRegistry_NilRegistryID verifies that a nil registry ID is skipped.
func TestLinkArtifactRegistry_NilRegistryID(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{}
	q := repository.New(db)
	// Neither ID valid → should be a no-op.
	err := linkArtifactRegistry(context.Background(), q, pgtype.UUID{}, pgtype.UUID{})
	is.NoErr(err)
}

// TestLinkArtifactRegistry_Success verifies the junction table upsert is called.
func TestLinkArtifactRegistry_Success(t *testing.T) {
	is := is.New(t)
	called := false
	db := &fakeDB{
		execFn: func(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
			called = true
			return pgconn.CommandTag{}, nil
		},
	}
	q := repository.New(db)
	err := linkArtifactRegistry(context.Background(), q, newUUID(t), newUUID2(t))
	is.NoErr(err)
	is.True(called)
}

// contains is a small helper to avoid importing strings in test assertions.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
