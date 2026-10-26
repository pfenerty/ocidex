package service

import (
	"bytes"
	"context"
	"sort"
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
type fakeLicense struct {
	id   pgtype.UUID
	spdx string
	name string
}

type fakeLink struct{ component, license pgtype.UUID }

type fakeBackfillRepo struct {
	licenses      []*fakeLicense
	links         map[fakeLink]bool
	nextLicense   byte
	componentRefs map[pgtype.UUID][]repository.ListSBOMComponentRefsRow
	exprSBOMs     []pgtype.UUID
	sboms         []*fakeBackfillSBOM
	components    []*fakeBackfillComponent
	listCalls     int
	purlPages     int
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
	f.purlPages++
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

	res, err := Backfill(context.Background(), repo, BackfillBatches{SBOMs: 2, Components: 2})
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
	again, err := Backfill(context.Background(), repo, BackfillBatches{SBOMs: 2, Components: 2})
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

	res, err := Backfill(context.Background(), repo, BackfillBatches{SBOMs: 2, Components: 2})
	is.NoErr(err)
	is.Equal(res.Purl.Updated, 5)
	// Purl pages of 2, 2 and 1, plus one call each for the empty flavor and
	// provenance steps.
	is.Equal(repo.listCalls, 5)
}

// TestBackfillPurlPagesByComponentBatch covers ocidex-ah9z: the purl step
// pages by the component batch, not the SBOM batch, so a table needing
// thousands of fixes is read in a few pages rather than one per 50 rows.
func TestBackfillPurlPagesByComponentBatch(t *testing.T) {
	is := is.New(t)
	repo := &fakeBackfillRepo{}
	for i := range 250 {
		repo.components = append(repo.components, &fakeBackfillComponent{
			id: seqUUID16(uint16(1000 + i)), purl: "pkg:golang/github.com/example/svc", version: "v1.5.0",
		})
	}
	res, err := Backfill(context.Background(), repo, BackfillBatches{SBOMs: 2, Components: 100})
	is.NoErr(err)
	is.Equal(res.Purl, BackfillCounts{Updated: 250})
	is.Equal(repo.purlPages, 3) // 100 + 100 + 50
}

// seqUUID16 is seqUUID for more than 255 ids.
func seqUUID16(n uint16) pgtype.UUID {
	u := pgtype.UUID{Valid: true}
	u.Bytes[14], u.Bytes[15] = byte(n>>8), byte(n)
	return u
}

// --- license backfill (ocidex-wb5k) ---

func (f *fakeBackfillRepo) license(id pgtype.UUID) *fakeLicense {
	for _, l := range f.licenses {
		if l.id == id {
			return l
		}
	}
	return nil
}

func (f *fakeBackfillRepo) addLicense(spdx, name string) pgtype.UUID {
	f.nextLicense++
	l := &fakeLicense{id: pgtype.UUID{Bytes: [16]byte{0xEE, f.nextLicense}, Valid: true}, spdx: spdx, name: name}
	f.licenses = append(f.licenses, l)
	return l.id
}

func (f *fakeBackfillRepo) GetLicenseBySPDX(_ context.Context, spdxID pgtype.Text) (repository.GetLicenseBySPDXRow, error) {
	for _, l := range f.licenses {
		if l.spdx == spdxID.String {
			return repository.GetLicenseBySPDXRow{ID: l.id, Name: l.name}, nil
		}
	}
	return repository.GetLicenseBySPDXRow{}, pgx.ErrNoRows
}

func (f *fakeBackfillRepo) GetLicenseByName(_ context.Context, name string) (repository.GetLicenseByNameRow, error) {
	for _, l := range f.licenses {
		if l.spdx == "" && l.name == name {
			return repository.GetLicenseByNameRow{ID: l.id}, nil
		}
	}
	return repository.GetLicenseByNameRow{}, pgx.ErrNoRows
}

func (f *fakeBackfillRepo) UpsertLicenseBySPDX(ctx context.Context, arg repository.UpsertLicenseBySPDXParams) (pgtype.UUID, error) {
	if row, err := f.GetLicenseBySPDX(ctx, arg.SpdxID); err == nil {
		f.license(row.ID).name = arg.Name
		return row.ID, nil
	}
	return f.addLicense(arg.SpdxID.String, arg.Name), nil
}

func (f *fakeBackfillRepo) UpsertLicenseByName(ctx context.Context, arg repository.UpsertLicenseByNameParams) (pgtype.UUID, error) {
	if row, err := f.GetLicenseByName(ctx, arg.Name); err == nil {
		return row.ID, nil
	}
	return f.addLicense("", arg.Name), nil
}

func (f *fakeBackfillRepo) ListNameOnlyLicensesPage(_ context.Context, arg repository.ListNameOnlyLicensesPageParams) ([]repository.ListNameOnlyLicensesPageRow, error) {
	var out []repository.ListNameOnlyLicensesPageRow
	for _, l := range f.licenses {
		if l.spdx == "" && after(l.id, arg.After) && len(out) < int(arg.RowLimit) {
			out = append(out, repository.ListNameOnlyLicensesPageRow{ID: l.id, Name: l.name})
		}
	}
	return out, nil
}

func (f *fakeBackfillRepo) CopyLicenseLinks(_ context.Context, arg repository.CopyLicenseLinksParams) error {
	for k := range f.links {
		if k.license == arg.FromLicense {
			f.links[fakeLink{k.component, arg.ToLicense}] = true
		}
	}
	return nil
}

func (f *fakeBackfillRepo) DeleteLicenseByID(_ context.Context, id pgtype.UUID) error {
	for i, l := range f.licenses {
		if l.id == id {
			f.licenses = append(f.licenses[:i], f.licenses[i+1:]...)
			break
		}
	}
	for k := range f.links {
		if k.license == id {
			delete(f.links, k)
		}
	}
	return nil
}

func (f *fakeBackfillRepo) ListSBOMIDsWithLicenseExpressionsPage(_ context.Context, arg repository.ListSBOMIDsWithLicenseExpressionsPageParams) ([]pgtype.UUID, error) {
	var out []pgtype.UUID
	for _, id := range f.exprSBOMs {
		if after(id, arg.After) && len(out) < int(arg.RowLimit) {
			out = append(out, id)
		}
	}
	return out, nil
}

func (f *fakeBackfillRepo) ListSBOMComponentRefs(_ context.Context, sbomID pgtype.UUID) ([]repository.ListSBOMComponentRefsRow, error) {
	return f.componentRefs[sbomID], nil
}

func (f *fakeBackfillRepo) InsertComponentLicenseIfMissing(_ context.Context, arg repository.InsertComponentLicenseIfMissingParams) (int64, error) {
	k := fakeLink{arg.ComponentID, arg.LicenseID}
	if f.links[k] {
		return 0, nil
	}
	f.links[k] = true
	return 1, nil
}

// licensesOf names the licenses a component is linked to, SPDX id first.
func (f *fakeBackfillRepo) licensesOf(component pgtype.UUID) []string {
	var out []string
	for k := range f.links {
		if k.component == component {
			if l := f.license(k.license); l != nil {
				if l.spdx != "" {
					out = append(out, l.spdx)
				} else {
					out = append(out, l.name)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// Licenses stored before ExpandLicense are re-derived from their names
// (ocidex-wb5k): expressions split, aliases map, junk goes, and the component
// keeps every license it really has.
func TestBackfillLicenseNames(t *testing.T) {
	is := is.New(t)
	comp := pgtype.UUID{Bytes: [16]byte{0xC1}, Valid: true}
	other := pgtype.UUID{Bytes: [16]byte{0xC2}, Valid: true}
	f := &fakeBackfillRepo{links: map[fakeLink]bool{}}
	mit := f.addLicense("MIT", "MIT License")
	expat := f.addLicense("", "Expat")
	expr := f.addLicense("", "EPL-2.0 AND GPL-2.0-only WITH Classpath-exception-2.0")
	junk := f.addLicense("", "AND")
	digest := f.addLicense("", "sha256:fd7e4aae7e7b05f217bcf2d02322825c360e66c52c4c2f1b28d784d6297a1c23")
	comma := f.addLicense("", "REGCOMP,")
	plain := f.addLicense("", "BSD-like")
	for _, l := range []pgtype.UUID{mit, expat, expr, junk, digest, comma, plain} {
		f.links[fakeLink{comp, l}] = true
	}
	f.links[fakeLink{other, expat}] = true

	got, err := backfillLicenseNames(context.Background(), f, 2)
	is.NoErr(err)
	is.Equal(got.Updated, 5) // Expat, the expression, AND, the digest, REGCOMP,
	// BSD-like is already as ExpandLicense would store it, and so is the
	// REGCOMP row this run created, which the same pass reaches later.
	is.Equal(got.Skipped, 2)

	is.Equal(f.licensesOf(comp), []string{"BSD-like", "EPL-2.0", "GPL-2.0-only WITH Classpath-exception-2.0", "MIT", "REGCOMP"})
	is.Equal(f.licensesOf(other), []string{"MIT"}) // Expat became MIT for every component
	for _, l := range f.licenses {
		is.True(l.name != "Expat" && l.name != "AND" && l.name != "REGCOMP,")
	}

	// A second run finds nothing left to do.
	again, err := backfillLicenseNames(context.Background(), f, 2)
	is.NoErr(err)
	is.Equal(again.Updated, 0)
}

// Pre-nps9.13 ingest skipped CycloneDX license expressions entirely; the
// backfill adds what they name, once.
func TestBackfillLicenseExpressions(t *testing.T) {
	is := is.New(t)
	sbomID := pgtype.UUID{Bytes: [16]byte{0x5B}, Valid: true}
	comp := pgtype.UUID{Bytes: [16]byte{0xC3}, Valid: true}
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"a","bom-ref":"ref-a","licenses":[{"expression":"MIT OR Apache-2.0"}]},
		{"type":"library","name":"b","licenses":[{"expression":"MIT"}]}]}`)
	f := &fakeBackfillRepo{
		links:         map[fakeLink]bool{},
		sboms:         []*fakeBackfillSBOM{{id: sbomID, rawBom: raw}},
		exprSBOMs:     []pgtype.UUID{sbomID},
		componentRefs: map[pgtype.UUID][]repository.ListSBOMComponentRefsRow{sbomID: {{ID: comp, BomRef: pgtype.Text{String: "ref-a", Valid: true}}}},
	}

	got, err := backfillLicenseExpressions(context.Background(), f, 10)
	is.NoErr(err)
	is.Equal(got.Updated, 2) // MIT and Apache-2.0 on component a
	is.Equal(got.Skipped, 1) // b has no bom-ref to match its row by
	is.Equal(f.licensesOf(comp), []string{"Apache-2.0", "MIT"})

	again, err := backfillLicenseExpressions(context.Background(), f, 10)
	is.NoErr(err)
	is.Equal(again.Updated, 0)
}
