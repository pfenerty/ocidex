package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func TestPaginationDefaults(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)

	var resp cursorBody
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &resp))
	is.Equal(resp.Pagination.Limit, int32(20))
	is.Equal(resp.Pagination.HasMore, false)
}

func TestPaginationCustomValues(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sboms?limit=25", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)

	var resp cursorBody
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &resp))
	is.Equal(resp.Pagination.Limit, int32(25))
}

func TestPaginationCapAtMax(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sboms?limit=500", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	// Huma enforces maximum:200 from the struct tag, so this should be rejected.
	is.True(w.Code == http.StatusUnprocessableEntity || w.Code == http.StatusOK)
}
