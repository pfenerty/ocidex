package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

// scanFnRows implements pgx.Rows where each row is defined by a scan function.
// Used to return multi-column results from fakeDB.queryFn.
type scanFnRows struct {
	fns []func(...any) error
	idx int
}

func (r *scanFnRows) Next() bool                                   { return r.idx < len(r.fns) }
func (r *scanFnRows) Err() error                                   { return nil }
func (r *scanFnRows) Close()                                       {}
func (r *scanFnRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *scanFnRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *scanFnRows) Values() ([]any, error)                       { return nil, nil }
func (r *scanFnRows) RawValues() [][]byte                          { return nil }
func (r *scanFnRows) Conn() *pgx.Conn                              { return nil }
func (r *scanFnRows) Scan(dest ...any) error {
	fn := r.fns[r.idx]
	r.idx++
	return fn(dest...)
}

// emptyRows returns a scanFnRows with no rows.
func emptyRows() *scanFnRows { return &scanFnRows{} }

// scanVisible returns a scan function for IsSBOMVisible / IsArtifactVisible (single bool).
func scanVisible(v bool) func(...any) error {
	return func(dest ...any) error {
		*(dest[0].(*bool)) = v
		return nil
	}
}

// scanComponentRow returns a scan function for GetComponentRow (15 fields).
// Only sets ID, SbomID, Type, Name, and FoundBy; remaining fields stay zero.
func scanComponentRow(id, sbomID pgtype.UUID, typ, name string) func(...any) error {
	return scanComponentRowWithFoundBy(id, sbomID, typ, name, "")
}

// scanComponentRowWithFoundBy is scanComponentRow with an explicit found_by
// value, for exercising GetComponent's derived Confidence mapping.
func scanComponentRowWithFoundBy(id, sbomID pgtype.UUID, typ, name, foundBy string) func(...any) error {
	return func(dest ...any) error {
		*(dest[0].(*pgtype.UUID)) = id
		*(dest[1].(*pgtype.UUID)) = sbomID
		// dest[2] ParentID (pgtype.UUID) — zero
		// dest[3] BomRef  (pgtype.Text)  — zero
		*(dest[4].(*string)) = typ
		*(dest[5].(*string)) = name
		// dest[6..13] GroupName, Version, Purl, Cpe, Description, Scope, Publisher, Copyright — zero
		if foundBy != "" {
			*(dest[14].(*pgtype.Text)) = pgtype.Text{String: foundBy, Valid: true}
		}
		// dest[15..16] SourcePurl, SourcePackage — zero
		return nil
	}
}

// scanComponentRowWithLayer is scanComponentRow with an explicit layer_id
// value, for exercising GetComponent's resolveComponentLayer path.
func scanComponentRowWithLayer(id, sbomID pgtype.UUID, typ, name, layerID string) func(...any) error {
	return func(dest ...any) error {
		*(dest[0].(*pgtype.UUID)) = id
		*(dest[1].(*pgtype.UUID)) = sbomID
		*(dest[4].(*string)) = typ
		*(dest[5].(*string)) = name
		if layerID != "" {
			*(dest[17].(*pgtype.Text)) = pgtype.Text{String: layerID, Valid: true}
		}
		return nil
	}
}

// scanEnrichment returns a scan function for the Enrichment row (8 fields),
// setting only Status and Data.
func scanEnrichment(status string, data []byte) func(...any) error {
	return func(dest ...any) error {
		*(dest[3].(*string)) = status
		*(dest[4].(*[]byte)) = data
		return nil
	}
}

// ---- SearchDistinctComponents tests ----

// TestSearchDistinctComponents_SortNormalization verifies that invalid Sort and
// SortDir values are clamped to the defaults ("name" / "asc") before the query
// is issued.
func TestSearchDistinctComponents_SortNormalization(t *testing.T) {
	tests := []struct {
		name        string
		sort        string
		sortDir     string
		wantSort    string
		wantSortDir string
	}{
		{"invalid both", "invalid", "bad", "name", "asc"},
		{"empty both", "", "", "name", "asc"},
		{"valid sort invalid dir", "version_count", "sideways", "version_count", "asc"},
		{"valid both", "sbom_count", "desc", "sbom_count", "desc"},
		{"name explicit", "name", "asc", "name", "asc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			var capturedSortBy, capturedSortDir string
			db := &fakeDB{
				queryFn: func(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
					// args positions match SearchDistinctComponents query:
					// 0=Name, 1=GroupName, 2=Type, 3=PurlType, 4=UserID, 5=IsAdmin,
					// 6=SortBy, 7=SortDir, 8=RowOffset, 9=RowLimit
					if len(args) >= 8 {
						capturedSortBy, _ = args[6].(string)
						capturedSortDir, _ = args[7].(string)
					}
					return emptyRows(), nil
				},
			}

			svc := NewSearchService(db)
			_, err := svc.SearchDistinctComponents(context.Background(), ComponentFilter{
				Sort:    tt.sort,
				SortDir: tt.sortDir,
				Limit:   10,
			})

			is.NoErr(err)
			is.Equal(capturedSortBy, tt.wantSort)
			is.Equal(capturedSortDir, tt.wantSortDir)
		})
	}
}

// TestSearchDistinctComponents_Pagination verifies that TotalCount from DB rows
// is mapped to PagedResult.Total and that Limit/Offset are preserved.
func TestSearchDistinctComponents_Pagination(t *testing.T) {
	is := is.New(t)

	row := func(dest ...any) error {
		*(dest[0].(*string)) = "openssl" // Name
		// dest[1] GroupName (pgtype.Text)  — zero
		*(dest[2].(*string)) = "library" // Type
		// dest[3] PurlTypes (interface{})  — zero
		*(dest[4].(*int64)) = 3  // VersionCount
		*(dest[5].(*int64)) = 5  // SbomCount
		*(dest[6].(*int64)) = 42 // TotalCount
		return nil
	}

	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return &scanFnRows{fns: []func(...any) error{row, row}}, nil
		},
	}

	svc := NewSearchService(db)
	result, err := svc.SearchDistinctComponents(context.Background(), ComponentFilter{
		Limit:  20,
		Offset: 40,
	})

	is.NoErr(err)
	is.Equal(result.Total, int64(42))
	is.Equal(result.Limit, int32(20))
	is.Equal(result.Offset, int32(40))
	is.Equal(len(result.Data), 2)
}

// TestSearchDistinctComponents_PurlTypeParsing verifies that a comma-separated
// purl_types string is split into a proper slice.
func TestSearchDistinctComponents_PurlTypeParsing(t *testing.T) {
	is := is.New(t)

	row := func(dest ...any) error {
		*(dest[0].(*string)) = "libssl"
		*(dest[2].(*string)) = "library"
		*(dest[3].(*interface{})) = "npm,pip,cargo" // PurlTypes
		*(dest[4].(*int64)) = 1
		*(dest[5].(*int64)) = 1
		*(dest[6].(*int64)) = 1
		return nil
	}

	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return &scanFnRows{fns: []func(...any) error{row}}, nil
		},
	}

	svc := NewSearchService(db)
	result, err := svc.SearchDistinctComponents(context.Background(), ComponentFilter{Limit: 10})
	is.NoErr(err)
	is.Equal(len(result.Data), 1)
	is.Equal(result.Data[0].PurlTypes, []string{"npm", "pip", "cargo"})
}

// TestSearchDistinctComponents_EmptyPurlTypes verifies that an empty purl_types
// string results in a nil/empty slice, not [""].
func TestSearchDistinctComponents_EmptyPurlTypes(t *testing.T) {
	is := is.New(t)

	row := func(dest ...any) error {
		*(dest[0].(*string)) = "libssl"
		*(dest[2].(*string)) = "library"
		*(dest[3].(*interface{})) = "" // empty
		*(dest[4].(*int64)) = 1
		*(dest[5].(*int64)) = 1
		*(dest[6].(*int64)) = 1
		return nil
	}

	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return &scanFnRows{fns: []func(...any) error{row}}, nil
		},
	}

	svc := NewSearchService(db)
	result, err := svc.SearchDistinctComponents(context.Background(), ComponentFilter{Limit: 10})
	is.NoErr(err)
	is.Equal(len(result.Data[0].PurlTypes), 0)
}

// ---- SearchComponents tests ----

// TestSearchComponents_EmptyResult verifies that an empty DB result returns a
// zero-total PagedResult with no data.
func TestSearchComponents_EmptyResult(t *testing.T) {
	is := is.New(t)

	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return emptyRows(), nil
		},
	}

	svc := NewSearchService(db)
	result, err := svc.SearchComponents(context.Background(), ComponentFilter{Limit: 25, Offset: 0})
	is.NoErr(err)
	is.Equal(result.Total, int64(0))
	is.Equal(len(result.Data), 0)
	is.Equal(result.Limit, int32(25))
}

// ---- GetComponent tests ----

// TestGetComponent_NotFound verifies that a missing component (pgx.ErrNoRows)
// returns ErrNotFound.
func TestGetComponent_NotFound(t *testing.T) {
	is := is.New(t)

	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return noRowsRow{}
		},
	}

	svc := NewSearchService(db)
	_, err := svc.GetComponent(context.Background(), newUUID(t), VisibilityFilter{})
	is.True(errors.Is(err, ErrNotFound))
}

// TestGetComponent_VisibilityDenied verifies that when the parent SBOM is not
// visible the service returns ErrNotFound even though the component itself exists.
func TestGetComponent_VisibilityDenied(t *testing.T) {
	is := is.New(t)

	compID := newUUID(t)
	sbomID := newUUID2(t)
	callIdx := 0

	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			callIdx++
			switch callIdx {
			case 1: // GetComponent
				return &fakeRow{scanFn: scanComponentRow(compID, sbomID, "library", "openssl")}
			case 2: // IsSBOMVisible
				return &fakeRow{scanFn: scanVisible(false)}
			default:
				return noRowsRow{}
			}
		},
	}

	svc := NewSearchService(db)
	_, err := svc.GetComponent(context.Background(), compID, VisibilityFilter{})
	is.True(errors.Is(err, ErrNotFound))
}

// TestGetComponent_Success verifies that a visible component returns a fully
// populated ComponentDetail (including empty hashes, licenses, and ext refs
// when the DB returns no sub-rows).
func TestGetComponent_Success(t *testing.T) {
	is := is.New(t)

	compID := newUUID(t)
	sbomID := newUUID2(t)
	callIdx := 0

	db := &fakeDB{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			callIdx++
			switch callIdx {
			case 1: // GetComponent
				return &fakeRow{scanFn: scanComponentRow(compID, sbomID, "library", "openssl")}
			case 2: // IsSBOMVisible
				return &fakeRow{scanFn: scanVisible(true)}
			default:
				return noRowsRow{}
			}
		},
		// Sub-queries (hashes, licenses, ext refs) all return empty.
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return emptyRows(), nil
		},
	}

	svc := NewSearchService(db)
	detail, err := svc.GetComponent(context.Background(), compID, VisibilityFilter{})

	is.NoErr(err)
	is.Equal(detail.Name, "openssl")
	is.Equal(detail.Type, "library")
	is.Equal(detail.SbomID, uuidToString(sbomID))
	is.Equal(len(detail.Hashes), 0)
	is.Equal(len(detail.Licenses), 0)
	is.Equal(len(detail.ExternalRefs), 0)
	is.True(detail.FoundBy == nil)
	is.True(detail.Confidence == nil)
}

// TestGetComponent_FoundByAndConfidence verifies FoundBy is passed through
// and Confidence is derived at read time: nil for any cataloger except
// binary-cataloger, which maps to "low".
func TestGetComponent_FoundByAndConfidence(t *testing.T) {
	tests := []struct {
		name           string
		foundBy        string
		wantFoundBy    *string
		wantConfidence *string
	}{
		{name: "db-backed cataloger", foundBy: "deb-db-cataloger", wantFoundBy: strPtr("deb-db-cataloger"), wantConfidence: nil},
		{name: "binary cataloger", foundBy: "binary-cataloger", wantFoundBy: strPtr("binary-cataloger"), wantConfidence: strPtr("low")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)

			compID := newUUID(t)
			sbomID := newUUID2(t)
			callIdx := 0

			db := &fakeDB{
				queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
					callIdx++
					switch callIdx {
					case 1: // GetComponent
						return &fakeRow{scanFn: scanComponentRowWithFoundBy(compID, sbomID, "library", "openssl", tc.foundBy)}
					case 2: // IsSBOMVisible
						return &fakeRow{scanFn: scanVisible(true)}
					default:
						return noRowsRow{}
					}
				},
				queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
					return emptyRows(), nil
				},
			}

			svc := NewSearchService(db)
			detail, err := svc.GetComponent(context.Background(), compID, VisibilityFilter{})

			is.NoErr(err)
			is.Equal(deref(detail.FoundBy), deref(tc.wantFoundBy))
			is.Equal(deref(detail.Confidence), deref(tc.wantConfidence))
		})
	}
}

// TestGetComponent_Layer verifies resolveComponentLayer: layer_id resolved
// to an ordinal via the oci-metadata enrichment's layer list, and the
// FromBaseImage heuristic (base declared + ordinal 0).
func TestGetComponent_Layer(t *testing.T) {
	baseMeta := []byte(`{
		"baseDigest": "sha256:basedigest",
		"layers": [
			{"ordinal": 0, "diffId": "sha256:layer0"},
			{"ordinal": 1, "diffId": "sha256:layer1"},
			{"ordinal": 2, "diffId": "sha256:layer2"}
		]
	}`)

	tests := []struct {
		name              string
		layerID           string
		enrichmentPresent bool
		wantLayerID       *string
		wantLayer         *int
		wantFromBase      bool
		wantEnrichmentGet bool
	}{
		{
			name:              "bottom layer of image with declared base",
			layerID:           "sha256:layer0",
			enrichmentPresent: true,
			wantLayerID:       strPtr("sha256:layer0"),
			wantLayer:         intPtr(0),
			wantFromBase:      true,
			wantEnrichmentGet: true,
		},
		{
			name:              "upper layer of image with declared base",
			layerID:           "sha256:layer2",
			enrichmentPresent: true,
			wantLayerID:       strPtr("sha256:layer2"),
			wantLayer:         intPtr(2),
			wantFromBase:      false,
			wantEnrichmentGet: true,
		},
		{
			name:              "layer_id set, no oci-metadata enrichment",
			layerID:           "sha256:layer0",
			enrichmentPresent: false,
			wantLayerID:       strPtr("sha256:layer0"),
			wantLayer:         nil,
			wantFromBase:      false,
			wantEnrichmentGet: true,
		},
		{
			name:              "layer_id unset",
			layerID:           "",
			enrichmentPresent: false,
			wantLayerID:       nil,
			wantLayer:         nil,
			wantFromBase:      false,
			wantEnrichmentGet: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)

			compID := newUUID(t)
			sbomID := newUUID2(t)
			callIdx := 0
			enrichmentCalled := false

			db := &fakeDB{
				queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
					callIdx++
					switch callIdx {
					case 1: // GetComponent
						return &fakeRow{scanFn: scanComponentRowWithLayer(compID, sbomID, "library", "openssl", tc.layerID)}
					case 2: // IsSBOMVisible
						return &fakeRow{scanFn: scanVisible(true)}
					case 3: // GetEnrichment
						enrichmentCalled = true
						if !tc.enrichmentPresent {
							return noRowsRow{}
						}
						return &fakeRow{scanFn: scanEnrichment("success", baseMeta)}
					default:
						return noRowsRow{}
					}
				},
				queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
					return emptyRows(), nil
				},
			}

			svc := NewSearchService(db)
			detail, err := svc.GetComponent(context.Background(), compID, VisibilityFilter{})

			is.NoErr(err)
			is.Equal(deref(detail.LayerID), deref(tc.wantLayerID))
			is.Equal(derefInt(detail.Layer), derefInt(tc.wantLayer))
			is.Equal(detail.FromBaseImage, tc.wantFromBase)
			is.Equal(enrichmentCalled, tc.wantEnrichmentGet)
		})
	}
}

func strPtr(s string) *string { return &s }

func intPtr(i int) *int { return &i }

func derefInt(i *int) int {
	if i == nil {
		return -1
	}
	return *i
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
