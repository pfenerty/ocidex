package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"
)

func TestMapServiceError_NotFound(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &notFoundSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/3e671687-395b-41f5-a30f-a58921a69b79", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusNotFound)
}

func TestMapServiceError_InternalError(t *testing.T) {
	is := is.New(t)
	router := newTestRouterWithAuth(&failSBOMService{}, &fakeSearchService{}, memberAuthSvc())

	body := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{"type": "library", "name": "test-lib", "version": "1.0.0"}
		]
	}`
	r := httptest.NewRequest(http.MethodPost, ingestPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer member-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusInternalServerError)
}

func TestBadUUIDPathParamIsRejected(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/not-a-uuid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusUnprocessableEntity)
}
