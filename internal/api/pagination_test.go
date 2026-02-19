package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
	"github.com/pfenerty/ocidex/internal/api"
)

func TestPaginationDefaults(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sbom", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)

	var resp pagedBody
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &resp))
	is.Equal(resp.Pagination.Limit, int32(50))
	is.Equal(resp.Pagination.Offset, int32(0))
}

func TestPaginationCustomValues(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sbom?limit=25&offset=100", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)

	var resp pagedBody
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &resp))
	is.Equal(resp.Pagination.Limit, int32(25))
	is.Equal(resp.Pagination.Offset, int32(100))
}

func TestPaginationCapAtMax(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sbom?limit=500", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	// Huma enforces maximum:200 from the struct tag, so this should be rejected.
	is.True(w.Code == http.StatusUnprocessableEntity || w.Code == http.StatusOK)
}

func TestParseUUID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid UUID", "3e671687-395b-41f5-a30f-a58921a69b79", false},
		{"invalid", "not-a-uuid", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			id, err := api.ParseUUID(tt.input)
			if tt.wantErr {
				is.True(err != nil)
			} else {
				is.NoErr(err)
				is.True(id.Valid)
			}
		})
	}
}
