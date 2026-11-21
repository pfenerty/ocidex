package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// memberAuthSvc returns a fakeAuthService that maps "member-token" to a member
// user holding maintainer in testNamespaceID — the namespace every ingest test
// posts a source in. Ingest is a capability now, not a property of who created
// the namespace, so the grant has to be stated rather than inferred from an
// owner column.
func memberAuthSvc() *fakeAuthService {
	return &fakeAuthService{
		users: map[string]service.AuthUser{
			"member-token": {ID: ownerUUID.String(), Role: "member"},
		},
		grants: map[string]map[string]authz.Role{
			ownerUUID.String(): {testNamespaceID: authz.RoleMaintainer},
		},
	}
}

// memberRouter returns a router with a wired member auth service (no registry
// service), where "member-token" is a maintainer in testNamespaceID.
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

			r := httptest.NewRequest(http.MethodPost, ingestPath, strings.NewReader(tt.body))
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
	r := httptest.NewRequest(http.MethodPost, ingestPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusUnauthorized)
}

func TestDeleteSBOM(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		namespaceID string
		wantStatus  int
	}{
		{"maintainer in its namespace", "01020304-0506-0708-090a-0b0c0d0e0f10", testNamespaceID, http.StatusNoContent},
		{"member of another namespace", "01020304-0506-0708-090a-0b0c0d0e0f10", mwNamespaceID, http.StatusForbidden},
		// A resource hanging from no namespace is admin-only (ocidex-avsz.3).
		{"no namespace", "01020304-0506-0708-090a-0b0c0d0e0f10", "", http.StatusForbidden},
		// invalid UUID: RequireCapability's resolve parses the id before huma's
		// format check runs, so it answers 404 rather than 422.
		{"bad uuid", "not-a-uuid", testNamespaceID, http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := memberRouter(&fakeSBOMService{namespaceID: tt.namespaceID})

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
		name        string
		id          string
		namespaceID string
		wantStatus  int
	}{
		{"maintainer in its namespace", "01020304-0506-0708-090a-0b0c0d0e0f10", testNamespaceID, http.StatusNoContent},
		{"member of another namespace", "01020304-0506-0708-090a-0b0c0d0e0f10", mwNamespaceID, http.StatusForbidden},
		// A resource hanging from no namespace is admin-only (ocidex-avsz.3).
		{"no namespace", "01020304-0506-0708-090a-0b0c0d0e0f10", "", http.StatusForbidden},
		// invalid UUID: RequireCapability's resolve parses the id before huma's
		// format check runs, so it answers 404 rather than 422.
		{"bad uuid", "not-a-uuid", testNamespaceID, http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := memberRouter(&fakeSBOMService{namespaceID: tt.namespaceID})

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
	r := httptest.NewRequest(http.MethodPost, ingestPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer member-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusInternalServerError)
}

// multiNSSBOMService hangs every artifact from several namespaces and records
// the scope a delete was confined to.
type multiNSSBOMService struct {
	fakeSBOMService
	namespaces []string
	deletedAll bool
	deletedIn  []string
}

func (f *multiNSSBOMService) ListArtifactNamespaceIDs(_ context.Context, _ string) ([]string, error) {
	return f.namespaces, nil
}

func (f *multiNSSBOMService) DeleteArtifact(_ context.Context, _ string) error {
	f.deletedAll = true
	return nil
}

func (f *multiNSSBOMService) DeleteArtifactFromNamespaces(_ context.Context, _ string, ids []string) error {
	f.deletedIn = append(f.deletedIn, ids...)
	return nil
}

// A shared artifact hanging from the caller's namespace and another tenant's:
// the delete is admitted (the caller holds delete_artifact in one of them,
// whichever sorts first) and confined to the caller's namespace.
func TestDeleteArtifact_SharedArtifactConfinedToCallerNamespaces(t *testing.T) {
	for _, order := range [][]string{
		{mwNamespaceID, testNamespaceID},
		{testNamespaceID, mwNamespaceID},
	} {
		is := is.New(t)
		svc := &multiNSSBOMService{namespaces: order}
		router := memberRouter(svc)

		r := httptest.NewRequest(http.MethodDelete, "/api/v1/artifacts/01020304-0506-0708-090a-0b0c0d0e0f10", nil)
		r.Header.Set("Authorization", "Bearer member-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		is.Equal(w.Code, http.StatusNoContent)
		is.True(!svc.deletedAll)
		is.Equal(svc.deletedIn, []string{testNamespaceID})
	}
}
