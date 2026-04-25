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

	_, err := svc.ListSBOMsByArtifact(context.Background(), uid, "", "", 10, 0, VisibilityFilter{})
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
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, errors.New("db error")
		},
	}
	svc := &searchService{db: db}

	_, err := svc.GetComponentVersions(context.Background(), "", "", "", "", VisibilityFilter{})
	is.True(err != nil)
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
