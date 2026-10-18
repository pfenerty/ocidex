package service

import (
	"bytes"
	"context"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// seqUUID returns a UUID that sorts by n, so keyset pages are predictable.
func seqUUID(n byte) pgtype.UUID {
	u := pgtype.UUID{Valid: true}
	u.Bytes[15] = n
	return u
}

func after(id, cursor pgtype.UUID) bool { return bytes.Compare(id.Bytes[:], cursor.Bytes[:]) > 0 }

type fakeBackfillSBOM struct {
	id             pgtype.UUID
	subjectVersion string
	flavor         pgtype.Text
	rawBom         []byte
}

type fakeBackfillComponent struct {
	id, sbomID     pgtype.UUID
	bomRef         string
	purl, version  string
	filePath       pgtype.Text
	provenanceSets int
}

// fakeBackfillRepo applies simplified versions of the db/queries/sbom.sql
// predicates over in-memory rows, and counts list calls to check paging.
type fakeBackfillRepo struct {
	sboms      []*fakeBackfillSBOM
	components []*fakeBackfillComponent
	listCalls  int
}

func (f *fakeBackfillRepo) ListSBOMsWithoutFlavorPage(_ context.Context, arg repository.ListSBOMsWithoutFlavorPageParams) ([]repository.ListSBOMsWithoutFlavorPageRow, error) {
	f.listCalls++
	var out []repository.ListSBOMsWithoutFlavorPageRow
	for _, s := range f.sboms {
		if after(s.id, arg.After) && s.flavor.String == "" && len(out) < int(arg.RowLimit) {
			out = append(out, repository.ListSBOMsWithoutFlavorPageRow{ID: s.id, SubjectVersion: pgtype.Text{String: s.subjectVersion, Valid: true}, RawBom: s.rawBom})
		}
	}
	return out, nil
}

func (f *fakeBackfillRepo) UpdateSBOMFlavor(_ context.Context, arg repository.UpdateSBOMFlavorParams) error {
	for _, s := range f.sboms {
		if s.id == arg.ID {
			s.flavor = arg.Flavor
		}
	}
	return nil
}

func (f *fakeBackfillRepo) ListComponentsWithUnversionedPurlPage(_ context.Context, arg repository.ListComponentsWithUnversionedPurlPageParams) ([]repository.ListComponentsWithUnversionedPurlPageRow, error) {
	f.listCalls++
	var out []repository.ListComponentsWithUnversionedPurlPageRow
	for _, c := range f.components {
		if after(c.id, arg.After) && c.version != "" && !bytes.Contains([]byte(c.purl), []byte("@")) && len(out) < int(arg.RowLimit) {
			out = append(out, repository.ListComponentsWithUnversionedPurlPageRow{ID: c.id, Purl: pgtype.Text{String: c.purl, Valid: true}, Version: pgtype.Text{String: c.version, Valid: true}})
		}
	}
	return out, nil
}

func (f *fakeBackfillRepo) UpdateComponentPurl(_ context.Context, arg repository.UpdateComponentPurlParams) error {
	for _, c := range f.components {
		if c.id == arg.ID {
			c.purl = arg.Purl.String
		}
	}
	return nil
}

func (f *fakeBackfillRepo) ListSBOMIDsWithMissingProvenancePage(_ context.Context, arg repository.ListSBOMIDsWithMissingProvenancePageParams) ([]pgtype.UUID, error) {
	f.listCalls++
	var out []pgtype.UUID
	for _, s := range f.sboms {
		if !after(s.id, arg.After) || len(out) >= int(arg.RowLimit) {
			continue
		}
		for _, c := range f.components {
			if c.sbomID == s.id && c.bomRef != "" && !c.filePath.Valid {
				out = append(out, s.id)
				break
			}
		}
	}
	return out, nil
}

func (f *fakeBackfillRepo) GetSBOMRawBomForBackfill(_ context.Context, id pgtype.UUID) (repository.GetSBOMRawBomForBackfillRow, error) {
	for _, s := range f.sboms {
		if s.id == id {
			return repository.GetSBOMRawBomForBackfillRow{Flavor: s.flavor, RawBom: s.rawBom}, nil
		}
	}
	return repository.GetSBOMRawBomForBackfillRow{}, pgx.ErrNoRows
}

func (f *fakeBackfillRepo) ListSBOMComponentsMissingProvenance(_ context.Context, sbomID pgtype.UUID) ([]repository.ListSBOMComponentsMissingProvenanceRow, error) {
	var out []repository.ListSBOMComponentsMissingProvenanceRow
	for _, c := range f.components {
		if c.sbomID == sbomID && c.bomRef != "" && !c.filePath.Valid {
			out = append(out, repository.ListSBOMComponentsMissingProvenanceRow{ID: c.id, BomRef: pgtype.Text{String: c.bomRef, Valid: true}, Purl: pgtype.Text{String: c.purl, Valid: true}})
		}
	}
	return out, nil
}

func (f *fakeBackfillRepo) UpdateComponentProvenance(_ context.Context, arg repository.UpdateComponentProvenanceParams) error {
	for _, c := range f.components {
		if c.id == arg.ID {
			c.filePath = arg.FilePath
			c.provenanceSets++
		}
	}
	return nil
}

func TestBackfill(t *testing.T) {
	is := is.New(t)

	located := []cdx.Property{
		{Name: "syft:location:0:layerID", Value: "sha256:layer1"},
		{Name: "syft:location:0:path", Value: "/usr/bin/svc"},
		{Name: "syft:package:foundBy", Value: "go-module-binary-cataloger"},
	}
	raw := rawBomFromComponents(t, []cdx.Component{
		{BOMRef: "located", Name: "svc", PackageURL: "pkg:golang/github.com/example/svc@v1.5.0", Properties: &located},
		{BOMRef: "unlocated", Name: "lib", PackageURL: "pkg:golang/github.com/example/lib@v1.0.0"},
	})

	repo := &fakeBackfillRepo{
		sboms: []*fakeBackfillSBOM{
			{id: seqUUID(1), subjectVersion: "v1.5.0", rawBom: raw},
			{id: seqUUID(2), subjectVersion: "v1.5.0", rawBom: raw},
			{id: seqUUID(3), subjectVersion: "v1.5.0", rawBom: []byte("not json"), flavor: pgtype.Text{String: "x", Valid: true}},
			{id: seqUUID(4), rawBom: []byte("not json")},
		},
		components: []*fakeBackfillComponent{
			{id: seqUUID(10), sbomID: seqUUID(1), bomRef: "located", purl: "pkg:golang/github.com/example/svc", version: "v1.5.0"},
			{id: seqUUID(11), sbomID: seqUUID(1), bomRef: "unlocated", purl: "pkg:golang/github.com/example/lib@v1.0.0", version: "v1.0.0"},
			{id: seqUUID(12), sbomID: seqUUID(2), bomRef: "located", purl: "pkg:golang/github.com/example/svc", version: "UNKNOWN"},
			{id: seqUUID(13), sbomID: seqUUID(3), bomRef: "located", purl: "pkg:golang/x@v1", version: "v1"},
		},
	}

	res, err := Backfill(context.Background(), repo, 2)
	is.NoErr(err)

	// Flavor: SBOMs 1 and 2 detected; SBOM 4's raw_bom does not decode. SBOM 3
	// already has one.
	is.Equal(res.Flavor, BackfillCounts{Updated: 2, Errored: 1})
	is.True(repo.sboms[0].flavor.Valid && repo.sboms[0].flavor.String != "")
	is.Equal(repo.sboms[2].flavor.String, "x")

	// Purl: the version is spliced into 10's purl; the rule declines 12, whose
	// version is unknown (the fake's predicate is looser than the SQL's).
	is.Equal(res.Purl, BackfillCounts{Updated: 1, Skipped: 1})
	is.Equal(repo.components[0].purl, "pkg:golang/github.com/example/svc@v1.5.0")
	is.Equal(repo.components[2].purl, "pkg:golang/github.com/example/svc")

	// Provenance: "located" gets its file path in SBOMs 1 and 2; "unlocated"
	// carries none, so it is left NULL; SBOM 3's raw_bom does not decode.
	is.Equal(res.Provenance, BackfillCounts{Updated: 2, Skipped: 1, Errored: 1})
	is.Equal(repo.components[0].filePath.String, "/usr/bin/svc")
	is.True(!repo.components[1].filePath.Valid)
	is.Equal(repo.components[2].filePath.String, "/usr/bin/svc")

	// Re-running only re-selects the rows no rule can fill.
	again, err := Backfill(context.Background(), repo, 2)
	is.NoErr(err)
	is.Equal(again.Flavor, BackfillCounts{Errored: 1})
	is.Equal(again.Purl, BackfillCounts{Skipped: 1})
	is.Equal(again.Provenance, BackfillCounts{Skipped: 1, Errored: 1})
	is.Equal(repo.components[0].provenanceSets, 1)
}

func TestBackfill_Pages(t *testing.T) {
	is := is.New(t)
	repo := &fakeBackfillRepo{}
	for i := byte(1); i <= 5; i++ {
		repo.components = append(repo.components, &fakeBackfillComponent{
			id: seqUUID(i), purl: "pkg:golang/github.com/example/m", version: "v1.0.0",
		})
	}

	res, err := Backfill(context.Background(), repo, 2)
	is.NoErr(err)
	is.Equal(res.Purl.Updated, 5)
	// Purl pages of 2, 2 and 1, plus one call each for the empty flavor and
	// provenance steps.
	is.Equal(repo.listCalls, 5)
}
