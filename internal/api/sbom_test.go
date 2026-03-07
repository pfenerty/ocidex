package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"
)

func TestIngestSBOM(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name: "valid minimal SBOM",
			body: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"components": [
					{"type": "library", "name": "test-lib", "version": "1.0.0"}
				]
			}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "invalid JSON",
			body:       `{not json`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty body",
			body:       ``,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing components",
			body: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5"
			}`,
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name: "empty components array",
			body: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"components": []
			}`,
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name: "multiple components",
			body: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
				"components": [
					{"type": "library", "name": "lib-a", "version": "1.0"},
					{"type": "library", "name": "lib-b", "version": "2.0"}
				]
			}`,
			wantStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

			r := httptest.NewRequest(http.MethodPost, "/api/v1/sboms", strings.NewReader(tt.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestDeleteSBOM(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		wantStatus int
	}{
		{"valid uuid", "01020304-0506-0708-090a-0b0c0d0e0f10", http.StatusNoContent},
		{"bad uuid", "not-a-uuid", http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

			r := httptest.NewRequest(http.MethodDelete, "/api/v1/sboms/"+tt.id, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, r)
			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestDeleteArtifact(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		wantStatus int
	}{
		{"valid uuid", "01020304-0506-0708-090a-0b0c0d0e0f10", http.StatusNoContent},
		{"bad uuid", "not-a-uuid", http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

			r := httptest.NewRequest(http.MethodDelete, "/api/v1/artifacts/"+tt.id, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, r)
			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestIngestSBOM_ServiceError(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&failSBOMService{}, &fakeSearchService{})

	body := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{"type": "library", "name": "test-lib", "version": "1.0.0"}
		]
	}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sboms", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusInternalServerError)
}
