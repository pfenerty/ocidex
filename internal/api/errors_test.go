package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"
	"github.com/pfenerty/ocidex/internal/api"
)

func TestMapServiceError_NotFound(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &notFoundSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sbom/3e671687-395b-41f5-a30f-a58921a69b79", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusNotFound)
}

func TestMapServiceError_InternalError(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&failSBOMService{}, &fakeSearchService{})

	body := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{"type": "library", "name": "test-lib", "version": "1.0.0"}
		]
	}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sbom", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusInternalServerError)
}

func TestParseUUID_Invalid(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sbom/not-a-uuid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusUnprocessableEntity)
}

func TestParseUUID_Valid(t *testing.T) {
	is := is.New(t)

	id, err := api.ParseUUID("3e671687-395b-41f5-a30f-a58921a69b79")
	is.NoErr(err)
	is.True(id.Valid)
}

func TestParseUUID_Empty(t *testing.T) {
	_, err := api.ParseUUID("")
	if err == nil {
		t.Fatal("expected error for empty UUID")
	}
}
