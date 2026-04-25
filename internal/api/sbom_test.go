package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"
	"github.com/pfenerty/ocidex/internal/service"
)

// memberAuthSvc returns a fakeAuthService that maps "member-token" to a member user.
func memberAuthSvc() *fakeAuthService {
	return &fakeAuthService{
		users: map[string]service.AuthUser{
			"member-token": {ID: ownerUUID, Role: "member"},
		},
	}
}

// memberRouter returns a router with a wired member auth service (no registry
// service), so RequireMember / RequireSBOMOwner / RequireArtifactOwner all
// pass for authenticated members when the resource has no registry owner.
func memberRouter(sbomSvc service.SBOMService) http.Handler {
	return newTestRouterWithAuth(sbomSvc, &fakeSearchService{}, memberAuthSvc())
}

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
			router := memberRouter(&fakeSBOMService{})

			r := httptest.NewRequest(http.MethodPost, "/api/v1/sboms", strings.NewReader(tt.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer member-token")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestIngestSBOM_Unauthenticated(t *testing.T) {
	is := is.New(t)
	router := memberRouter(&fakeSBOMService{})

	body := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [{"type": "library", "name": "lib", "version": "1.0"}]
	}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sboms", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusUnauthorized)
}

func TestDeleteSBOM(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		wantStatus int
	}{
		// fakeSBOMService.GetSBOMRegistryID returns zero UUID → no owner → member allowed
		{"valid uuid", "01020304-0506-0708-090a-0b0c0d0e0f10", http.StatusNoContent},
		// invalid UUID: test router has nil registryService so middleware skips ownership
		// check and calls next; huma then validates format:"uuid" → 422
		{"bad uuid", "not-a-uuid", http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := memberRouter(&fakeSBOMService{})

			r := httptest.NewRequest(http.MethodDelete, "/api/v1/sboms/"+tt.id, nil)
			r.Header.Set("Authorization", "Bearer member-token")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, r)
			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestDeleteSBOM_Unauthenticated(t *testing.T) {
	is := is.New(t)
	router := memberRouter(&fakeSBOMService{})

	r := httptest.NewRequest(http.MethodDelete, "/api/v1/sboms/01020304-0506-0708-090a-0b0c0d0e0f10", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusUnauthorized)
}

func TestDeleteArtifact(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		wantStatus int
	}{
		// fakeSBOMService.GetArtifactOwnerID returns zero UUID → no owner → member allowed
		{"valid uuid", "01020304-0506-0708-090a-0b0c0d0e0f10", http.StatusNoContent},
		// invalid UUID: test router has nil registryService so middleware skips ownership
		// check and calls next; huma then validates format:"uuid" → 422
		{"bad uuid", "not-a-uuid", http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := memberRouter(&fakeSBOMService{})

			r := httptest.NewRequest(http.MethodDelete, "/api/v1/artifacts/"+tt.id, nil)
			r.Header.Set("Authorization", "Bearer member-token")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, r)
			is.Equal(w.Code, tt.wantStatus)
		})
	}
}

func TestDeleteArtifact_Unauthenticated(t *testing.T) {
	is := is.New(t)
	router := memberRouter(&fakeSBOMService{})

	r := httptest.NewRequest(http.MethodDelete, "/api/v1/artifacts/01020304-0506-0708-090a-0b0c0d0e0f10", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusUnauthorized)
}

func TestIngestSBOM_ServiceError(t *testing.T) {
	is := is.New(t)
	router := memberRouter(&failSBOMService{})

	body := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{"type": "library", "name": "test-lib", "version": "1.0.0"}
		]
	}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sboms", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer member-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusInternalServerError)
}
