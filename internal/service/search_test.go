package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

// newSearchSvc is a helper that builds a searchService with a fakeDB configured
// via the provided queryRowFn.
func newSearchSvc(queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row) *searchService {
	return &searchService{db: &fakeDB{queryRowFn: queryRowFn}}
}

// ---------------------------------------------------------------------------
// GetSBOM
// ---------------------------------------------------------------------------

func TestGetSBOM_NotVisible(t *testing.T) {
	is := is.New(t)
	svc := newSearchSvc(func(_ context.Context, _ string, _ ...any) pgx.Row {
		return &fakeRow{scanFn: func(dest ...any) error {
			if b, ok := dest[0].(*bool); ok {
				*b = false
			}
			return nil
		}}
	})
	uid := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}

	_, err := svc.GetSBOM(context.Background(), uid, false, VisibilityFilter{})
	is.Equal(err, ErrNotFound)
}

func TestGetSBOM_DBError(t *testing.T) {
	is := is.New(t)
	svc := newSearchSvc(func(_ context.Context, _ string, _ ...any) pgx.Row {
		return &fakeRow{scanFn: func(_ ...any) error {
			return errors.New("connection reset")
		}}
	})
	uid := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}

	_, err := svc.GetSBOM(context.Background(), uid, false, VisibilityFilter{})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// ListSBOMs
// ---------------------------------------------------------------------------

func TestListSBOMs_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}

	_, err := svc.ListSBOMs(context.Background(), SBOMFilter{})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// GetArtifact
// ---------------------------------------------------------------------------

func TestGetArtifact_NotVisible(t *testing.T) {
	is := is.New(t)
	svc := newSearchSvc(func(_ context.Context, _ string, _ ...any) pgx.Row {
		return &fakeRow{scanFn: func(dest ...any) error {
			if b, ok := dest[0].(*bool); ok {
				*b = false
			}
			return nil
		}}
	})
	uid := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}

	_, err := svc.GetArtifact(context.Background(), uid, VisibilityFilter{})
	is.Equal(err, ErrNotFound)
}

func TestGetArtifact_DBError(t *testing.T) {
	is := is.New(t)
	svc := newSearchSvc(func(_ context.Context, _ string, _ ...any) pgx.Row {
		return &fakeRow{scanFn: func(_ ...any) error {
			return errors.New("db error")
		}}
	})
	uid := pgtype.UUID{Bytes: [16]byte{4}, Valid: true}

	_, err := svc.GetArtifact(context.Background(), uid, VisibilityFilter{})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// ListArtifacts
// ---------------------------------------------------------------------------

func TestListArtifacts_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}

	_, err := svc.ListArtifacts(context.Background(), ArtifactFilter{})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// GetSBOMDependencies
// ---------------------------------------------------------------------------

func TestGetSBOMDependencies_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}
	uid := pgtype.UUID{Bytes: [16]byte{5}, Valid: true}

	_, err := svc.GetSBOMDependencies(context.Background(), uid, VisibilityFilter{})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// ListSBOMComponents
// ---------------------------------------------------------------------------

func TestListSBOMComponents_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}
	uid := pgtype.UUID{Bytes: [16]byte{6}, Valid: true}

	_, err := svc.ListSBOMComponents(context.Background(), uid, VisibilityFilter{})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// ListSBOMsByArtifact / ListSBOMsByDigest
// ---------------------------------------------------------------------------

func TestListSBOMsByArtifact_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}
	uid := pgtype.UUID{Bytes: [16]byte{7}, Valid: true}

	_, err := svc.ListSBOMsByArtifact(context.Background(), uid, "", "", SBOMByArtifactPage{Limit: 10}, VisibilityFilter{})
	is.True(err != nil)
}

func TestListSBOMsByDigest_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}

	_, err := svc.ListSBOMsByDigest(context.Background(), "sha256:abc", 10, 0, VisibilityFilter{})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// GetArtifactLicenseSummary
// ---------------------------------------------------------------------------

func TestGetArtifactLicenseSummary_DBError(t *testing.T) {
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
	svc := &searchService{db: db}
	uid := pgtype.UUID{Bytes: [16]byte{8}, Valid: true}

	_, err := svc.GetArtifactLicenseSummary(context.Background(), uid, VisibilityFilter{})
	is.Equal(err, ErrNotFound)
}

// ---------------------------------------------------------------------------
// ListLicenses / ListComponentsByLicense
// ---------------------------------------------------------------------------

func TestListLicenses_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}

	_, err := svc.ListLicenses(context.Background(), LicenseFilter{})
	is.True(err != nil)
}

func TestListComponentsByLicense_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}
	uid := pgtype.UUID{Bytes: [16]byte{9}, Valid: true}

	_, err := svc.ListComponentsByLicense(context.Background(), uid, 10, 0, VisibilityFilter{})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// GetComponentVersions / ListComponentPurlTypes
// ---------------------------------------------------------------------------

func TestGetComponentVersions_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		// The count runs first, so it has to succeed for the page query's
		// error to be the one under test.
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				if n, ok := dest[0].(*int64); ok {
					*n = 7
				}
				return nil
			}}
		},
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}

	_, err := svc.GetComponentVersions(context.Background(), ComponentVersionFilter{})
	is.True(err != nil)
}

func TestGetComponentVersions_CountError(t *testing.T) {
	is := is.New(t)
	pageQueried := false
	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(...any) error { return errors.New("db error") }}
		},
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			pageQueried = true
			return nil, nil
		},
	}
	svc := &searchService{db: db}

	_, err := svc.GetComponentVersions(context.Background(), ComponentVersionFilter{})
	is.True(err != nil)
	// A failed count must not be reported as a page of zero rows.
	is.True(!pageQueried)
}

// The endpoint returned every row a component name had ever produced. The
// most-used names have thousands, and the query carries three LEFT JOINs and a
// four-key sort, so /components' top rows -- the ones most likely to be clicked
// -- timed out at 30s (ocidex-ag4q.7). This pins that the caller's window
// actually reaches the query, and that the total is counted separately rather
// than derived from the page.
func TestGetComponentVersions_PassesWindowAndCountsSeparately(t *testing.T) {
	is := is.New(t)
	var pageArgs []any
	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				if n, ok := dest[0].(*int64); ok {
					*n = 4210
				}
				return nil
			}}
		},
		queryFn: func(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
			pageArgs = args
			return nil, errors.New("stop after capturing the window")
		},
	}
	svc := &searchService{db: db}

	_, err := svc.GetComponentVersions(context.Background(), ComponentVersionFilter{
		Name:   "golang.org/x/crypto",
		Limit:  20,
		Offset: 40,
	})
	is.True(err != nil)
	is.True(containsArg(pageArgs, int32(20)))
	is.True(containsArg(pageArgs, int32(40)))

	// And with a working page query, the total is the counted value, not len(rows).
	db.queryFn = func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
		return emptyRows(), nil
	}
	result, err := svc.GetComponentVersions(context.Background(), ComponentVersionFilter{
		Name:   "golang.org/x/crypto",
		Limit:  20,
		Offset: 40,
	})
	is.NoErr(err)
	is.Equal(len(result.Data), 0)
	is.Equal(result.Total, int64(4210))
	is.Equal(result.Limit, int32(20))
	is.Equal(result.Offset, int32(40))
}

// The two corpus-wide figures ride on the count query rather than the page, so
// they must survive the trip out through the embedded PagedResult. A band that
// reported len(page) versions would say "20 versions" for every component with
// more than a page of occurrences, which is the failure this pins.
func TestGetComponentVersions_ReportsCorpusWideCounts(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				// total, version_count, artifact_count — deliberately three
				// different numbers, so a mix-up cannot pass.
				for i, v := range []int64{4210, 37, 12} {
					n, ok := dest[i].(*int64)
					if !ok {
						return errors.New("unexpected scan target")
					}
					*n = v
				}
				return nil
			}}
		},
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return emptyRows(), nil
		},
	}
	svc := &searchService{db: db}

	result, err := svc.GetComponentVersions(context.Background(), ComponentVersionFilter{
		Name: "golang.org/x/crypto",
	})
	is.NoErr(err)
	is.Equal(result.Total, int64(4210))
	is.Equal(result.VersionCount, int64(37))
	is.Equal(result.ArtifactCount, int64(12))
}

func containsArg(args []any, want any) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestListComponentPurlTypes_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}

	_, err := svc.ListComponentPurlTypes(context.Background(), VisibilityFilter{})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// GetDashboardStats
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// classifyLicense
// ---------------------------------------------------------------------------

func TestClassifyLicense_Nil(t *testing.T) {
	is := is.New(t)
	is.Equal(classifyLicense(nil), "uncategorized")
}

func TestClassifyLicense_Copyleft(t *testing.T) {
	is := is.New(t)
	gpl := "GPL-3.0-only"
	is.Equal(classifyLicense(&gpl), "copyleft")
}

func TestClassifyLicense_Permissive(t *testing.T) {
	is := is.New(t)
	mit := "MIT"
	result := classifyLicense(&mit)
	is.Equal(result, "permissive")
}

func TestClassifyLicense_Uncategorized(t *testing.T) {
	is := is.New(t)
	// An invalid SPDX ID should return "uncategorized".
	invalid := "NotAnSPDXId!!!"
	result := classifyLicense(&invalid)
	is.Equal(result, "uncategorized")
}

func TestGetDashboardStats_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(_ ...any) error {
				return errors.New("db error")
			}}
		},
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}

	_, err := svc.GetDashboardStats(context.Background(), VisibilityFilter{})
	is.True(err != nil)
}

func TestUUIDToString(t *testing.T) {
	tests := []struct {
		name string
		id   pgtype.UUID
		want string
	}{
		{
			"valid",
			pgtype.UUID{Bytes: [16]byte{0x3e, 0x67, 0x16, 0x87, 0x39, 0x5b, 0x41, 0xf5, 0xa3, 0x0f, 0xa5, 0x89, 0x21, 0xa6, 0x9b, 0x79}, Valid: true},
			"3e671687-395b-41f5-a30f-a58921a69b79",
		},
		{"invalid", pgtype.UUID{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(uuidToString(tt.id), tt.want)
		})
	}
}

func TestTextToPtr(t *testing.T) {
	tests := []struct {
		name    string
		input   pgtype.Text
		wantNil bool
		wantVal string
	}{
		{"valid", pgtype.Text{String: "hello", Valid: true}, false, "hello"},
		{"null", pgtype.Text{}, true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			result := textToPtr(tt.input)
			if tt.wantNil {
				is.True(result == nil)
			} else {
				is.True(result != nil)
				is.Equal(*result, tt.wantVal)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ListSBOMDriftHistory
// ---------------------------------------------------------------------------

func TestListSBOMDriftHistory_NotVisible(t *testing.T) {
	is := is.New(t)
	svc := newSearchSvc(func(_ context.Context, _ string, _ ...any) pgx.Row {
		return &fakeRow{scanFn: func(dest ...any) error {
			if b, ok := dest[0].(*bool); ok {
				*b = false
			}
			return nil
		}}
	})
	uid := pgtype.UUID{Bytes: [16]byte{10}, Valid: true}

	_, err := svc.ListSBOMDriftHistory(context.Background(), uid, DriftPage{Limit: 10}, VisibilityFilter{})
	is.Equal(err, ErrNotFound)
}

func TestListSBOMDriftHistory_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				if b, ok := dest[0].(*bool); ok {
					*b = true
				}
				return nil
			}}
		},
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}
	uid := pgtype.UUID{Bytes: [16]byte{11}, Valid: true}

	_, err := svc.ListSBOMDriftHistory(context.Background(), uid, DriftPage{Limit: 10}, VisibilityFilter{})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// currentDrift
// ---------------------------------------------------------------------------

func TestCurrentDrift(t *testing.T) {
	is := is.New(t)

	is.Equal(currentDrift(nil, "verified"), nil)

	active := &ProvenanceDriftSummary{PreviousStatus: "verified", NewStatus: "artifact_missing"}
	is.Equal(currentDrift(active, "artifact_missing"), active)

	stale := &ProvenanceDriftSummary{PreviousStatus: "verified", NewStatus: "artifact_missing"}
	is.Equal(currentDrift(stale, "verified"), nil)
}

// ---------------------------------------------------------------------------
// ListRecentProvenanceDrift
// ---------------------------------------------------------------------------

func TestListRecentProvenanceDrift_DBError(t *testing.T) {
	is := is.New(t)
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}

	_, err := svc.ListRecentProvenanceDrift(context.Background(), DriftPage{Limit: 10}, VisibilityFilter{IsAdmin: true})
	is.True(err != nil)
}
