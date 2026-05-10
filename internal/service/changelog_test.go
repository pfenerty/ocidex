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
// buildComponentMap / buildPackageMap
// ---------------------------------------------------------------------------

func TestBuildPackageMap(t *testing.T) {
	is := is.New(t)
	rows := []repository.ListSBOMPackagesRow{
		{
			Type:    "library",
			Name:    "curl",
			Version: pgtype.Text{String: "7.81.0", Valid: true},
		},
		{
			Type:    "library",
			Name:    "openssl",
			Version: pgtype.Text{String: "3.0.0", Valid: true},
			Purl:    pgtype.Text{String: "pkg:deb/ubuntu/openssl@3.0.0", Valid: true},
		},
	}

	m := buildPackageMap(rows)

	is.Equal(len(m), 2)
	is.True(m["library\x00curl\x00"].version != nil)
	is.Equal(*m["library\x00curl\x00"].version, "7.81.0")
	is.True(m["pkg:deb/ubuntu/openssl"] != (componentIdentity{}))
}

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

	// "1.0"→"2.0" classifies as upgraded, not modified.
	is.Equal(entry.Summary.Upgraded, 1)
	is.Equal(entry.Summary.Modified, 0)
	is.Equal(entry.Summary.Added, 1)
	is.Equal(entry.Summary.Removed, 1)
	is.Equal(len(entry.Changes), 3)

	// Verify sort order: removed first, then modified/upgraded, then added.
	is.Equal(entry.Changes[0].Type, "removed")
	is.Equal(entry.Changes[1].Type, "modified")
	is.Equal(entry.Changes[1].Direction, "upgraded")
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

func TestFilterByArchAndFlavor(t *testing.T) {
	is := is.New(t)
	best := map[changelogGroupKey]changelogCandidate{
		{"v1", "amd64", "standard"}: {arch: "amd64", flavor: "standard"},
		{"v1", "arm64", "standard"}: {arch: "arm64", flavor: "standard"},
		{"v2", "amd64", "standard"}: {arch: "amd64", flavor: "standard"},
		{"v1", "amd64", "fips"}:     {arch: "amd64", flavor: "fips"},
	}
	amd64standard := filterByArchAndFlavor(best, "amd64", "standard")
	is.Equal(len(amd64standard), 2)
	for _, c := range amd64standard {
		is.Equal(c.arch, "amd64")
		is.Equal(c.flavor, "standard")
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

	best, available, _ := deduplicateSBOMs(sboms, meta)

	// Both have same (version, arch, flavor) key — should keep only the later one.
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

	best, _, _ := deduplicateSBOMs(sboms, meta)
	is.Equal(len(best), 2)
}

func TestDeduplicateSBOMs_SeparateFlavorsSameVersionArch(t *testing.T) {
	is := is.New(t)
	uid1 := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	uid2 := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}

	sboms := []repository.ListSBOMsByArtifactRow{
		{ID: uid1, SubjectVersion: pgtype.Text{String: "v1", Valid: true}, Flavor: pgtype.Text{String: "alpine", Valid: true}, CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
		{ID: uid2, SubjectVersion: pgtype.Text{String: "v1", Valid: true}, Flavor: pgtype.Text{String: "debian", Valid: true}, CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
	}
	meta := map[pgtype.UUID]enrichmentMeta{
		uid1: {architecture: "amd64"},
		uid2: {architecture: "amd64"},
	}

	best, _, availableFlavors := deduplicateSBOMs(sboms, meta)

	is.Equal(len(best), 2)
	is.True(availableFlavors["alpine"])
	is.True(availableFlavors["debian"])
}

func TestDeduplicateSBOMs_SameFlavorTripleDeduplicates(t *testing.T) {
	is := is.New(t)
	t1 := time.Now().Add(-time.Hour)
	t2 := time.Now()
	uid1 := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	uid2 := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}

	sboms := []repository.ListSBOMsByArtifactRow{
		{ID: uid1, SubjectVersion: pgtype.Text{String: "v1", Valid: true}, Flavor: pgtype.Text{String: "alpine", Valid: true}, CreatedAt: pgtype.Timestamptz{Time: t1, Valid: true}},
		{ID: uid2, SubjectVersion: pgtype.Text{String: "v1", Valid: true}, Flavor: pgtype.Text{String: "alpine", Valid: true}, CreatedAt: pgtype.Timestamptz{Time: t2, Valid: true}},
	}
	meta := map[pgtype.UUID]enrichmentMeta{
		uid1: {architecture: "amd64"},
		uid2: {architecture: "amd64"},
	}

	best, _, _ := deduplicateSBOMs(sboms, meta)

	is.Equal(len(best), 1)
	for _, c := range best {
		is.Equal(c.sbom.ID, uid2)
	}
}

func TestDeduplicateSBOMs_ThreeWaySplit(t *testing.T) {
	is := is.New(t)
	uid1 := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	uid2 := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	uid3 := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}

	sboms := []repository.ListSBOMsByArtifactRow{
		{ID: uid1, SubjectVersion: pgtype.Text{String: "v1", Valid: true}, Flavor: pgtype.Text{String: "alpine", Valid: true}, CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
		{ID: uid2, SubjectVersion: pgtype.Text{String: "v1", Valid: true}, Flavor: pgtype.Text{String: "debian", Valid: true}, CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
		{ID: uid3, SubjectVersion: pgtype.Text{String: "v1", Valid: true}, Flavor: pgtype.Text{String: "alpine", Valid: true}, CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
	}
	meta := map[pgtype.UUID]enrichmentMeta{
		uid1: {architecture: "amd64"},
		uid2: {architecture: "amd64"},
		uid3: {architecture: "arm64"},
	}

	best, available, availableFlavors := deduplicateSBOMs(sboms, meta)

	is.Equal(len(best), 3)
	is.True(available["amd64"])
	is.True(available["arm64"])
	is.True(availableFlavors["alpine"])
	is.True(availableFlavors["debian"])
}

// ---------------------------------------------------------------------------
// selectFlavor
// ---------------------------------------------------------------------------

func TestSelectFlavor_RequestedPresent(t *testing.T) {
	is := is.New(t)
	available := map[string]bool{"alpine": true, "debian": true}
	is.Equal(selectFlavor("debian", available), "debian")
}

func TestSelectFlavor_RequestedAbsent_FallsBackToAlphabetical(t *testing.T) {
	is := is.New(t)
	available := map[string]bool{"alpine": true, "debian": true}
	is.Equal(selectFlavor("wolfi", available), "alpine") // wolfi missing; alpine < debian
}

func TestSelectFlavor_EmptyRequest_PicksAlphabetical(t *testing.T) {
	is := is.New(t)
	available := map[string]bool{"debian": true, "alpine": true}
	is.Equal(selectFlavor("", available), "alpine")
}

func TestSelectFlavor_OnlyUnknownAvailable(t *testing.T) {
	is := is.New(t)
	available := map[string]bool{"unknown": true}
	is.Equal(selectFlavor("", available), "unknown")
}

func TestSelectFlavor_EmptyAvailable(t *testing.T) {
	is := is.New(t)
	is.Equal(selectFlavor("", map[string]bool{}), "")
}

func TestSelectFlavor_SkipsUnknownForAlphabetical(t *testing.T) {
	is := is.New(t)
	available := map[string]bool{"unknown": true, "alpine": true, "debian": true}
	is.Equal(selectFlavor("", available), "alpine") // unknown skipped; alpine < debian
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

	_, err := svc.GetArtifactChangelog(context.Background(), uid, "", "", "", VisibilityFilter{})
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

	cl, err := svc.GetArtifactChangelog(context.Background(), uid, "", "", "", VisibilityFilter{IsAdmin: true})
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

// ---------------------------------------------------------------------------
// normalizeComponentPurl (E2 — ADR 0019 Rule 1)
// ---------------------------------------------------------------------------

func TestNormalizeComponentPurl(t *testing.T) {
	tests := []struct {
		name string
		purl string
		want string
	}{
		{
			name: "strips version, no qualifiers",
			purl: "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.15",
			want: "pkg:deb/ubuntu/curl",
		},
		{
			name: "strips version, keeps identity qualifier",
			purl: "pkg:deb/ubuntu/curl@7.81.0?arch=amd64",
			want: "pkg:deb/ubuntu/curl?arch=amd64",
		},
		{
			name: "drops noise qualifier download_url",
			purl: "pkg:apk/wolfi/curl@8.6.0?download_url=https://a.example",
			want: "pkg:apk/wolfi/curl",
		},
		{
			name: "keeps distro, drops download_url",
			purl: "pkg:apk/wolfi/curl@8.6.0?distro=wolfi-os&download_url=https://a.example",
			want: "pkg:apk/wolfi/curl?distro=wolfi-os",
		},
		{
			name: "sorts identity qualifiers alphabetically (distro version stripped)",
			purl: "pkg:deb/ubuntu/curl@7.0?epoch=1&arch=amd64&distro=ubuntu-22.04",
			want: "pkg:deb/ubuntu/curl?arch=amd64&distro=ubuntu&epoch=1",
		},
		{
			name: "qualifier order normalization — same result (distro version stripped)",
			purl: "pkg:deb/ubuntu/curl@7.0?distro=ubuntu-22.04&arch=amd64",
			want: "pkg:deb/ubuntu/curl?arch=amd64&distro=ubuntu",
		},
		{
			name: "unknown qualifier treated as noise",
			purl: "pkg:npm/lodash@4.17.21?some_future_qualifier=x",
			want: "pkg:npm/lodash",
		},
		{
			name: "no version, no qualifiers",
			purl: "pkg:deb/ubuntu/curl",
			want: "pkg:deb/ubuntu/curl",
		},
		{
			name: "all qualifiers are noise — returns bare path",
			purl: "pkg:deb/ubuntu/curl@1.0?checksum=sha256:abc&tag=latest&commit=deadbeef",
			want: "pkg:deb/ubuntu/curl",
		},
		{
			name: "repository_url is identity",
			purl: "pkg:deb/ubuntu/curl@1.0?repository_url=https://ppa.example",
			want: "pkg:deb/ubuntu/curl?repository_url=https://ppa.example",
		},
		{
			name: "distro family kept, version stripped (alpine 3.14.3)",
			purl: "pkg:apk/alpine/curl@8.0?distro=alpine-3.14.3",
			want: "pkg:apk/alpine/curl?distro=alpine",
		},
		{
			name: "distro family kept, version stripped (alpine 3.15.0)",
			purl: "pkg:apk/alpine/curl@8.0?distro=alpine-3.15.0",
			want: "pkg:apk/alpine/curl?distro=alpine",
		},
		{
			name: "distro family kept, version stripped (fedora 34)",
			purl: "pkg:rpm/fedora/curl@8.0?distro=fedora-34",
			want: "pkg:rpm/fedora/curl?distro=fedora",
		},
		{
			name: "distro family kept, version stripped (debian 12)",
			purl: "pkg:deb/debian/curl@8.0?distro=debian-12",
			want: "pkg:deb/debian/curl?distro=debian",
		},
		{
			name: "distro 'wolfi-os' has no numeric suffix — unchanged",
			purl: "pkg:apk/wolfi/curl@8.0?distro=wolfi-os",
			want: "pkg:apk/wolfi/curl?distro=wolfi-os",
		},
		{
			name: "distro 'chainguard' bare — unchanged",
			purl: "pkg:apk/chainguard/curl@8.0?distro=chainguard",
			want: "pkg:apk/chainguard/curl?distro=chainguard",
		},
		{
			name: "distro normalization preserves alphabetical qualifier sort",
			purl: "pkg:apk/alpine/curl@8.0?distro=alpine-3.15.0&arch=aarch64",
			want: "pkg:apk/alpine/curl?arch=aarch64&distro=alpine",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(normalizeComponentPurl(tc.purl), tc.want)
		})
	}
}

// ---------------------------------------------------------------------------
// reconcileVersionedPackages survivor guard (E1 — ADR 0019 Rule 3)
// ---------------------------------------------------------------------------

func TestDiffComponents_SurvivorGuard(t *testing.T) {
	from := SBOMRef{ID: "aaa"}
	to := SBOMRef{ID: "bbb"}
	v := func(s string) *string { return &s }

	tests := []struct {
		name         string
		oldMap       map[string]componentIdentity
		newMap       map[string]componentIdentity
		wantUpgraded int
		wantAdded    int
		wantRemoved  int
	}{
		{
			name: "clean upgrade — no survivor — collapses to modified",
			oldMap: map[string]componentIdentity{
				"library\x00gcc-11\x00": {version: v("11")},
			},
			newMap: map[string]componentIdentity{
				"library\x00gcc-12\x00": {version: v("12")},
			},
			wantUpgraded: 1,
		},
		{
			name: "survivor exists — does not collapse",
			oldMap: map[string]componentIdentity{
				"library\x00gcc-11\x00": {version: v("11")},
				"library\x00gcc-12\x00": {version: v("12")},
			},
			newMap: map[string]componentIdentity{
				"library\x00gcc-12\x00": {version: v("12")},
				"library\x00gcc-13\x00": {version: v("13")},
			},
			// gcc-12 unchanged; gcc-11 removed; gcc-13 added. No collapse.
			wantRemoved: 1,
			wantAdded:   1,
		},
		{
			name: "multi-add same base — does not collapse",
			oldMap: map[string]componentIdentity{
				"library\x00gcc-11\x00": {version: v("11")},
			},
			newMap: map[string]componentIdentity{
				"library\x00gcc-12\x00": {version: v("12")},
				"library\x00gcc-13\x00": {version: v("13")},
			},
			// Two new versions added, one old removed. No collapse.
			wantRemoved: 1,
			wantAdded:   2,
		},
		{
			name: "same name after stripping — no collapse (same-name guard)",
			oldMap: map[string]componentIdentity{
				"library\x00libssl1\x00": {version: v("1.0")},
			},
			newMap: map[string]componentIdentity{
				"library\x00libssl1\x00": {version: v("2.0")},
			},
			// Same component key — treated as upgraded directly, versionedNormKey returns "" (no dash).
			wantUpgraded: 1,
		},
		{
			name: "purl-based upgrade with qualifier — collapses correctly",
			oldMap: map[string]componentIdentity{
				"pkg:deb/ubuntu/gcc-11?arch=amd64": {version: v("11")},
			},
			newMap: map[string]componentIdentity{
				"pkg:deb/ubuntu/gcc-12?arch=amd64": {version: v("12")},
			},
			wantUpgraded: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			entry := diffComponents(from, to, tc.oldMap, tc.newMap)
			is.Equal(entry.Summary.Upgraded, tc.wantUpgraded)
			is.Equal(entry.Summary.Added, tc.wantAdded)
			is.Equal(entry.Summary.Removed, tc.wantRemoved)
		})
	}
}

// ---------------------------------------------------------------------------
// E3: Diff identity edge cases (ADR 0019)
// ---------------------------------------------------------------------------

func TestDiffComponents_VersionedNameEdgeCases(t *testing.T) {
	from := SBOMRef{ID: "aaa"}
	to := SBOMRef{ID: "bbb"}
	v := func(s string) *string { return &s }
	p := func(s string) *string { return &s }

	tests := []struct {
		name                string
		oldMap              map[string]componentIdentity
		newMap              map[string]componentIdentity
		wantUpgraded        int
		wantAdded           int
		wantRemoved         int
		wantUpgradedName    string // if non-empty, verify a Modified entry has this name
		wantPreviousVersion string // if non-empty, verify that entry's PreviousVersion
	}{
		{
			// versionSuffixRe handles dots: "-1.24" matches `-[0-9][0-9.]*$`
			name: "go dotted version suffix — collapses to upgraded",
			oldMap: map[string]componentIdentity{
				"library\x00go-1.24\x00": {version: v("1.24")},
			},
			newMap: map[string]componentIdentity{
				"library\x00go-1.25\x00": {version: v("1.25")},
			},
			wantUpgraded:        1,
			wantUpgradedName:    "go-1.25",
			wantPreviousVersion: "1.24",
		},
		{
			// gcc-12 persists unchanged → newNormCount["pkg:deb/ubuntu/gcc"]=2 → survivor guard fires
			name: "gcc-11+gcc-12 → gcc-12+gcc-13 via purl — survivor guard prevents collapse",
			oldMap: map[string]componentIdentity{
				"pkg:deb/ubuntu/gcc-11?arch=amd64": {version: v("11"), purl: p("pkg:deb/ubuntu/gcc-11@11?arch=amd64")},
				"pkg:deb/ubuntu/gcc-12?arch=amd64": {version: v("12"), purl: p("pkg:deb/ubuntu/gcc-12@12?arch=amd64")},
			},
			newMap: map[string]componentIdentity{
				"pkg:deb/ubuntu/gcc-12?arch=amd64": {version: v("12"), purl: p("pkg:deb/ubuntu/gcc-12@12?arch=amd64")},
				"pkg:deb/ubuntu/gcc-13?arch=amd64": {version: v("13"), purl: p("pkg:deb/ubuntu/gcc-13@13?arch=amd64")},
			},
			wantRemoved: 1,
			wantAdded:   1,
		},
		{
			// arch qualifier is in identityQualifiers → amd64 and arm64 are distinct identities
			name: "curl amd64 and arm64 upgrade independently — arch qualifies identity",
			oldMap: map[string]componentIdentity{
				"pkg:deb/ubuntu/curl?arch=amd64": {version: v("7.81.0"), purl: p("pkg:deb/ubuntu/curl@7.81.0?arch=amd64")},
				"pkg:deb/ubuntu/curl?arch=arm64": {version: v("7.81.0"), purl: p("pkg:deb/ubuntu/curl@7.81.0?arch=arm64")},
			},
			newMap: map[string]componentIdentity{
				"pkg:deb/ubuntu/curl?arch=amd64": {version: v("7.82.0"), purl: p("pkg:deb/ubuntu/curl@7.82.0?arch=amd64")},
				"pkg:deb/ubuntu/curl?arch=arm64": {version: v("7.82.0"), purl: p("pkg:deb/ubuntu/curl@7.82.0?arch=arm64")},
			},
			wantUpgraded: 2,
		},
		{
			// distro qualifier is in identityQualifiers → alpine-3.17 and wolfi are distinct identities;
			// busybox has no version suffix so versionedNormKey returns "" → no reconciliation
			name: "busybox alpine-3.17 vs wolfi — distro qualifier separates identities",
			oldMap: map[string]componentIdentity{
				"pkg:apk/alpine/busybox?distro=alpine-3.17": {version: v("1.35.0"), purl: p("pkg:apk/alpine/busybox@1.35.0?distro=alpine-3.17")},
			},
			newMap: map[string]componentIdentity{
				"pkg:apk/wolfi/busybox?distro=wolfi": {version: v("1.36.1"), purl: p("pkg:apk/wolfi/busybox@1.36.1?distro=wolfi")},
			},
			wantRemoved: 1,
			wantAdded:   1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			entry := diffComponents(from, to, tc.oldMap, tc.newMap)
			is.Equal(entry.Summary.Upgraded, tc.wantUpgraded)
			is.Equal(entry.Summary.Added, tc.wantAdded)
			is.Equal(entry.Summary.Removed, tc.wantRemoved)
			if tc.wantUpgradedName != "" {
				var found *ComponentDiff
				for i := range entry.Changes {
					if entry.Changes[i].Type == dirModified && entry.Changes[i].Name == tc.wantUpgradedName {
						found = &entry.Changes[i]
						break
					}
				}
				is.True(found != nil)
				if found != nil && tc.wantPreviousVersion != "" {
					is.True(found.PreviousVersion != nil)
					is.Equal(*found.PreviousVersion, tc.wantPreviousVersion)
				}
			}
		})
	}
}

// TestDiffComponents_DistroVersionDrift verifies that packages whose only
// difference between two SBOMs is the distro qualifier version (alpine-3.14.3
// → alpine-3.15.0) collapse to a single upgrade rather than reporting as
// remove+add. Goes through buildPackageMap so the test exercises the full
// production normalization path.
func TestDiffComponents_DistroVersionDrift(t *testing.T) {
	is := is.New(t)
	tx := func(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }

	oldRows := []repository.ListSBOMPackagesRow{
		{
			Type:    "library",
			Name:    "alpine-baselayout",
			Version: tx("3.2.0-r16"),
			Purl:    tx("pkg:apk/alpine/alpine-baselayout@3.2.0-r16?arch=aarch64&distro=alpine-3.14.3"),
		},
		{
			Type:    "library",
			Name:    "musl",
			Version: tx("1.2.2-r3"),
			Purl:    tx("pkg:apk/alpine/musl@1.2.2-r3?arch=aarch64&distro=alpine-3.14.3"),
		},
	}
	newRows := []repository.ListSBOMPackagesRow{
		{
			Type:    "library",
			Name:    "alpine-baselayout",
			Version: tx("3.2.0-r18"),
			Purl:    tx("pkg:apk/alpine/alpine-baselayout@3.2.0-r18?arch=aarch64&distro=alpine-3.15.0"),
		},
		{
			Type:    "library",
			Name:    "musl",
			Version: tx("1.2.2-r7"),
			Purl:    tx("pkg:apk/alpine/musl@1.2.2-r7?arch=aarch64&distro=alpine-3.15.0"),
		},
	}

	entry := diffComponents(SBOMRef{ID: "a"}, SBOMRef{ID: "b"}, buildPackageMap(oldRows), buildPackageMap(newRows))
	is.Equal(entry.Summary.Upgraded, 2)
	is.Equal(entry.Summary.Added, 0)
	is.Equal(entry.Summary.Removed, 0)
}

// TestDiffComponents_DistroFamiliesStayDistinct verifies that distro
// normalization preserves the alpine vs wolfi vs chainguard distinction
// (the original purpose of the qualifier-as-identity rule).
func TestDiffComponents_DistroFamiliesStayDistinct(t *testing.T) {
	is := is.New(t)
	tx := func(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }

	oldRows := []repository.ListSBOMPackagesRow{
		{
			Type:    "library",
			Name:    "curl",
			Version: tx("8.0"),
			Purl:    tx("pkg:apk/alpine/curl@8.0?distro=alpine-3.15.0"),
		},
	}
	newRows := []repository.ListSBOMPackagesRow{
		{
			Type:    "library",
			Name:    "curl",
			Version: tx("8.0"),
			Purl:    tx("pkg:apk/wolfi/curl@8.0?distro=wolfi-os"),
		},
	}

	entry := diffComponents(SBOMRef{ID: "a"}, SBOMRef{ID: "b"}, buildPackageMap(oldRows), buildPackageMap(newRows))
	is.Equal(entry.Summary.Removed, 1)
	is.Equal(entry.Summary.Added, 1)
	is.Equal(entry.Summary.Upgraded, 0)
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
