package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// ---------------------------------------------------------------------------
// compareVersionStrings
// ---------------------------------------------------------------------------

func TestCompareVersionStrings(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.2.4", "1.2.3", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.10.0", "1.9.0", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1", "1.0", -1},
		{"1.0.0", "1.0", 1},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			is := is.New(t)
			is.Equal(compareVersionStrings(tt.a, tt.b), tt.want)
		})
	}
}

// ---------------------------------------------------------------------------
// laterThan
// ---------------------------------------------------------------------------

func TestLaterThan_UsesIngestionTimeWhenNoBuildDate(t *testing.T) {
	is := is.New(t)
	t1 := time.Now()
	t2 := t1.Add(-time.Hour)

	is.True(laterThan(nil, t1, nil, t2))
	is.True(!laterThan(nil, t2, nil, t1))
}

func TestLaterThan_PrefersBuildDateOverIngestionTime(t *testing.T) {
	is := is.New(t)
	early := time.Now().Add(-24 * time.Hour)
	late := time.Now()
	recent := time.Now().Add(time.Minute)

	// bd1 is early but t1 is recent; bd2 is late.
	// Should compare build dates: early < late.
	is.True(!laterThan(&early, recent, &late, early))
	is.True(laterThan(&late, early, &early, recent))
}

func TestLaterThan_FallsBackToIngestionTimeOnEqualBuildDates(t *testing.T) {
	is := is.New(t)
	bd := time.Now()
	t1 := time.Now().Add(time.Minute)
	t2 := time.Now()

	is.True(laterThan(&bd, t1, &bd, t2))
}

// ---------------------------------------------------------------------------
// selectArch
// ---------------------------------------------------------------------------

func TestSelectArch_RequestedPresent(t *testing.T) {
	is := is.New(t)
	available := map[string]bool{"amd64": true, "arm64": true}
	is.Equal(selectArch("arm64", available), "arm64")
}

func TestSelectArch_RequestedAbsent_FallsBackToPreference(t *testing.T) {
	is := is.New(t)
	available := map[string]bool{"arm64": true, "arm": true}
	is.Equal(selectArch("amd64", available), "arm64") // amd64 missing, arm64 preferred next
}

func TestSelectArch_EmptyRequest_PicksPreferred(t *testing.T) {
	is := is.New(t)
	available := map[string]bool{"386": true}
	is.Equal(selectArch("", available), "386")
}

func TestSelectArch_EmptyAvailable(t *testing.T) {
	is := is.New(t)
	is.Equal(selectArch("", map[string]bool{}), "")
}

// ---------------------------------------------------------------------------
// nonEmptyStrPtr
// ---------------------------------------------------------------------------

func TestNonEmptyStrPtr_NonEmpty(t *testing.T) {
	is := is.New(t)
	p := nonEmptyStrPtr("hello")
	is.True(p != nil)
	is.Equal(*p, "hello")
}

func TestNonEmptyStrPtr_Empty(t *testing.T) {
	is := is.New(t)
	is.True(nonEmptyStrPtr("") == nil)
}

// ---------------------------------------------------------------------------
// componentKey / stripPurlVersion
// ---------------------------------------------------------------------------

func TestStripPurlVersion(t *testing.T) {
	is := is.New(t)
	is.Equal(stripPurlVersion("pkg:deb/ubuntu/curl@7.81.0"), "pkg:deb/ubuntu/curl")
	is.Equal(stripPurlVersion("pkg:deb/ubuntu/curl"), "pkg:deb/ubuntu/curl")
	is.Equal(stripPurlVersion(""), "")
}

func TestComponentKey_WithPurl(t *testing.T) {
	is := is.New(t)
	key := componentKey("library", "curl", pgtype.Text{}, pgtype.Text{String: "pkg:deb/ubuntu/curl@7.81.0", Valid: true})
	is.Equal(key, "pkg:deb/ubuntu/curl")
}

func TestComponentKey_WithoutPurl(t *testing.T) {
	is := is.New(t)
	key := componentKey("library", "curl", pgtype.Text{String: "ubuntu", Valid: true}, pgtype.Text{})
	is.Equal(key, "library\x00curl\x00ubuntu")
}

func TestComponentKey_WithoutPurlOrGroup(t *testing.T) {
	is := is.New(t)
	key := componentKey("library", "curl", pgtype.Text{}, pgtype.Text{})
	is.Equal(key, "library\x00curl\x00")
}

// ---------------------------------------------------------------------------
// nameFromKey / groupFromKey
// ---------------------------------------------------------------------------

func TestNameFromKey_TupleKey(t *testing.T) {
	is := is.New(t)
	is.Equal(nameFromKey("library\x00curl\x00ubuntu"), "curl")
}

func TestNameFromKey_PurlKey(t *testing.T) {
	is := is.New(t)
	is.Equal(nameFromKey("pkg:deb/ubuntu/curl"), "curl")
}

func TestNameFromKey_PurlKeyWithQuery(t *testing.T) {
	is := is.New(t)
	is.Equal(nameFromKey("pkg:deb/ubuntu/curl?arch=amd64"), "curl")
}

func TestGroupFromKey_TupleWithGroup(t *testing.T) {
	is := is.New(t)
	g := groupFromKey("library\x00curl\x00ubuntu")
	is.True(g != nil)
	is.Equal(*g, "ubuntu")
}

func TestGroupFromKey_TupleNoGroup(t *testing.T) {
	is := is.New(t)
	is.True(groupFromKey("library\x00curl\x00") == nil)
}

func TestGroupFromKey_PurlKey(t *testing.T) {
	is := is.New(t)
	is.True(groupFromKey("pkg:deb/ubuntu/curl") == nil)
}

// ---------------------------------------------------------------------------
// versionsEqual
// ---------------------------------------------------------------------------

func TestVersionsEqual(t *testing.T) {
	is := is.New(t)
	a := "1.0"
	b := "1.0"
	c := "2.0"

	is.True(versionsEqual(nil, nil))
	is.True(versionsEqual(&a, &b))
	is.True(!versionsEqual(&a, &c))
	is.True(!versionsEqual(&a, nil))
	is.True(!versionsEqual(nil, &b))
}

// ---------------------------------------------------------------------------
// buildComponentMap
// ---------------------------------------------------------------------------

func TestBuildComponentMap(t *testing.T) {
	is := is.New(t)
	rows := []repository.ListSBOMComponentsRow{
		{
			Type:    "library",
			Name:    "openssl",
			Version: pgtype.Text{String: "3.0.0", Valid: true},
		},
		{
			Type:    "library",
			Name:    "curl",
			Version: pgtype.Text{String: "7.81.0", Valid: true},
			Purl:    pgtype.Text{String: "pkg:deb/ubuntu/curl@7.81.0", Valid: true},
		},
	}

	m := buildComponentMap(rows)

	is.Equal(len(m), 2)
	is.True(m["library\x00openssl\x00"].version != nil)
	is.Equal(*m["library\x00openssl\x00"].version, "3.0.0")
	is.True(m["pkg:deb/ubuntu/curl"] != (componentIdentity{}))
}

// ---------------------------------------------------------------------------
// diffComponents
// ---------------------------------------------------------------------------

func TestDiffComponents_AddedRemovedModified(t *testing.T) {
	is := is.New(t)

	v1 := "1.0"
	v2 := "2.0"
	from := SBOMRef{ID: "aaa"}
	to := SBOMRef{ID: "bbb"}

	oldMap := map[string]componentIdentity{
		"pkg:deb/curl":    {version: &v1},
		"pkg:deb/removed": {version: &v1},
	}
	newMap := map[string]componentIdentity{
		"pkg:deb/curl":  {version: &v2}, // modified
		"pkg:deb/added": {version: &v1}, // added
	}

	entry := diffComponents(from, to, oldMap, newMap)

	is.Equal(entry.Summary.Modified, 1)
	is.Equal(entry.Summary.Added, 1)
	is.Equal(entry.Summary.Removed, 1)
	is.Equal(len(entry.Changes), 3)

	// Verify sort order: removed first, then modified, then added.
	is.Equal(entry.Changes[0].Type, "removed")
	is.Equal(entry.Changes[1].Type, "modified")
	is.Equal(entry.Changes[2].Type, "added")
}

// ---------------------------------------------------------------------------
// ValidationError.Error (errors.go)
// ---------------------------------------------------------------------------

func TestValidationError_Error(t *testing.T) {
	is := is.New(t)
	e := &ValidationError{Message: "bad input"}
	is.Equal(e.Error(), "bad input")
}

// ---------------------------------------------------------------------------
// candidateEffectiveTime / candidateLess / sortCandidates
// ---------------------------------------------------------------------------

func TestCandidateEffectiveTime_WithBuildDate(t *testing.T) {
	is := is.New(t)
	bd := time.Now().Add(-time.Hour)
	c := changelogCandidate{buildDate: &bd}
	is.Equal(candidateEffectiveTime(c), bd)
}

func TestCandidateEffectiveTime_NoBuildDate(t *testing.T) {
	is := is.New(t)
	ingested := time.Now()
	c := changelogCandidate{
		sbom: repository.ListSBOMsByArtifactRow{
			CreatedAt: pgtype.Timestamptz{Time: ingested, Valid: true},
		},
	}
	is.Equal(candidateEffectiveTime(c).UTC(), ingested.UTC())
}

func TestSortCandidates_ByVersion(t *testing.T) {
	is := is.New(t)
	mkCandidate := func(version string) changelogCandidate {
		return changelogCandidate{
			sbom: repository.ListSBOMsByArtifactRow{
				SubjectVersion: pgtype.Text{String: version, Valid: true},
				CreatedAt:      pgtype.Timestamptz{Time: time.Now(), Valid: true},
			},
		}
	}
	candidates := []changelogCandidate{
		mkCandidate("1.10.0"),
		mkCandidate("1.2.0"),
		mkCandidate("1.9.0"),
	}
	sortCandidates(candidates)
	is.Equal(candidates[0].sbom.SubjectVersion.String, "1.2.0")
	is.Equal(candidates[1].sbom.SubjectVersion.String, "1.9.0")
	is.Equal(candidates[2].sbom.SubjectVersion.String, "1.10.0")
}

func TestSortCandidates_FallsBackToIngestionTime(t *testing.T) {
	is := is.New(t)
	t1 := time.Now().Add(-time.Hour)
	t2 := time.Now()
	candidates := []changelogCandidate{
		{sbom: repository.ListSBOMsByArtifactRow{CreatedAt: pgtype.Timestamptz{Time: t2, Valid: true}}},
		{sbom: repository.ListSBOMsByArtifactRow{CreatedAt: pgtype.Timestamptz{Time: t1, Valid: true}}},
	}
	sortCandidates(candidates)
	// Earlier ingestion time should be first.
	is.Equal(candidates[0].sbom.CreatedAt.Time.UTC(), t1.UTC())
}

// ---------------------------------------------------------------------------
// filterByArch
// ---------------------------------------------------------------------------

func TestFilterByArch(t *testing.T) {
	is := is.New(t)
	best := map[changelogGroupKey]changelogCandidate{
		{"v1", "amd64"}: {arch: "amd64"},
		{"v1", "arm64"}: {arch: "arm64"},
		{"v2", "amd64"}: {arch: "amd64"},
	}
	amd64 := filterByArch(best, "amd64")
	is.Equal(len(amd64), 2)
	for _, c := range amd64 {
		is.Equal(c.arch, "amd64")
	}
}

// ---------------------------------------------------------------------------
// deduplicateSBOMs
// ---------------------------------------------------------------------------

func TestDeduplicateSBOMs_KeepsLatestPerGroup(t *testing.T) {
	is := is.New(t)
	t1 := time.Now().Add(-time.Hour)
	t2 := time.Now()

	uid1 := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	uid2 := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}

	sboms := []repository.ListSBOMsByArtifactRow{
		{ID: uid1, SubjectVersion: pgtype.Text{String: "v1", Valid: true}, CreatedAt: pgtype.Timestamptz{Time: t1, Valid: true}},
		{ID: uid2, SubjectVersion: pgtype.Text{String: "v1", Valid: true}, CreatedAt: pgtype.Timestamptz{Time: t2, Valid: true}},
	}
	meta := map[pgtype.UUID]enrichmentMeta{
		uid1: {architecture: "amd64"},
		uid2: {architecture: "amd64"},
	}

	best, available := deduplicateSBOMs(sboms, meta)

	// Both have same (version, arch) key — should keep only the later one.
	is.Equal(len(best), 1)
	is.True(available["amd64"])
	for _, c := range best {
		is.Equal(c.sbom.ID, uid2) // uid2 is later
	}
}

func TestDeduplicateSBOMs_SeparateGroups(t *testing.T) {
	is := is.New(t)
	uid1 := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	uid2 := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}

	sboms := []repository.ListSBOMsByArtifactRow{
		{ID: uid1, SubjectVersion: pgtype.Text{String: "v1", Valid: true}, CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
		{ID: uid2, SubjectVersion: pgtype.Text{String: "v2", Valid: true}, CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
	}
	meta := map[pgtype.UUID]enrichmentMeta{
		uid1: {architecture: "amd64"},
		uid2: {architecture: "amd64"},
	}

	best, _ := deduplicateSBOMs(sboms, meta)
	is.Equal(len(best), 2)
}

func TestDiffComponents_Unchanged(t *testing.T) {
	is := is.New(t)
	v := "1.0"
	from := SBOMRef{ID: "x"}
	to := SBOMRef{ID: "y"}

	m := map[string]componentIdentity{"pkg:deb/curl": {version: &v}}
	entry := diffComponents(from, to, m, m)

	is.Equal(entry.Summary.Added, 0)
	is.Equal(entry.Summary.Removed, 0)
	is.Equal(entry.Summary.Modified, 0)
	is.Equal(len(entry.Changes), 0)
}

// ---------------------------------------------------------------------------
// sbomToRef
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// DiffSBOMs via fakeDB
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// GetArtifactChangelog via fakeDB
// ---------------------------------------------------------------------------

func TestGetArtifactChangelog_NotVisible(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				// IsArtifactVisible returns false.
				if b, ok := dest[0].(*bool); ok {
					*b = false
				}
				return nil
			}}
		},
	}
	svc := NewSearchService(db)
	uid := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}

	_, err := svc.GetArtifactChangelog(context.Background(), uid, "", "", VisibilityFilter{})
	is.Equal(err, ErrNotFound)
}

func TestGetArtifactChangelog_EmptyChangelog(t *testing.T) {
	is := is.New(t)
	callCount := 0
	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			callCount++
			return &fakeRow{scanFn: func(dest ...any) error {
				// IsArtifactVisible returns true.
				if b, ok := dest[0].(*bool); ok {
					*b = true
				}
				return nil
			}}
		},
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			// ListSBOMsByArtifact and ListSBOMEnrichmentsByArtifact return empty rows.
			return &scanFnRows{}, nil
		},
	}
	svc := NewSearchService(db)
	uid := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}

	cl, err := svc.GetArtifactChangelog(context.Background(), uid, "", "", VisibilityFilter{IsAdmin: true})
	is.NoErr(err)
	is.Equal(len(cl.Entries), 0)
}

func TestDiffSBOMs_NotVisible(t *testing.T) {
	is := is.New(t)
	// IsSBOMVisible returns false → DiffSBOMs should return ErrNotFound.
	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				// IsSBOMVisible scans a single bool.
				if b, ok := dest[0].(*bool); ok {
					*b = false
				}
				return nil
			}}
		},
	}
	svc := NewSearchService(db)
	uid := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}

	_, err := svc.DiffSBOMs(context.Background(), uid, uid, VisibilityFilter{})
	is.Equal(err, ErrNotFound)
}

func TestDiffSBOMs_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(_ ...any) error {
				return errors.New("db error")
			}}
		},
	}
	svc := NewSearchService(db)
	uid := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}

	_, err := svc.DiffSBOMs(context.Background(), uid, uid, VisibilityFilter{})
	is.True(err != nil)
}

func TestSbomToRef(t *testing.T) {
	is := is.New(t)
	id := pgtype.UUID{Bytes: [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, Valid: true}
	ts := time.Now()
	row := repository.ListSBOMsByArtifactRow{
		ID:             id,
		SubjectVersion: pgtype.Text{String: "v1.2.3", Valid: true},
		CreatedAt:      pgtype.Timestamptz{Time: ts, Valid: true},
	}

	ref := sbomToRef(row)

	is.Equal(ref.ID, "01020304-0506-0708-090a-0b0c0d0e0f10")
	is.True(ref.SubjectVersion != nil)
	is.Equal(*ref.SubjectVersion, "v1.2.3")
	is.Equal(ref.CreatedAt.UTC(), ts.UTC())
}
