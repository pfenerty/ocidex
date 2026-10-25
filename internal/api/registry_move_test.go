package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/service"
)

// sourceNamespaceID is where the registry starts; testNamespaceID is the target.
const sourceNamespaceID = "0a0b0c0d-0e0f-1011-1213-141516171819"

// movingRegistryService records MoveNamespace calls.
type movingRegistryService struct {
	fakeRegistryService
	moved []string
}

func (m *movingRegistryService) MoveNamespace(_ context.Context, id, namespaceID string) error {
	m.moved = append(m.moved, id+"→"+namespaceID)
	return nil
}

const moveRegistryBody = `{"name":"r","type":"generic","url":"registry.example.com","insecure":false,"enabled":true,"namespace":"test-ns"}`

// TestUpdateRegistry_NamespaceMove covers ocidex-nps9.33: update moves a
// registry into an existing namespace only with manage_source there, a
// non-member of the target gets 404, and a missing namespace is never minted.
func TestUpdateRegistry_NamespaceMove(t *testing.T) {
	allCaps := authz.AllCapabilities()
	auth := &fakeAuthService{
		users: map[string]service.AuthUser{
			"owner-token":     {ID: ownerUUID, Role: "member", APIKeyAuth: true, APIKeyCaps: allCaps},
			"developer-token": {ID: developerUUID, Role: "member", APIKeyAuth: true, APIKeyCaps: allCaps},
			"stranger-token":  {ID: strangerUUID, Role: "member", APIKeyAuth: true, APIKeyCaps: allCaps},
		},
		// Everyone may manage the registry where it is; only the owner may
		// manage sources in the target.
		grants: map[string]map[string]authz.Role{
			uuidString(ownerUUID):     {sourceNamespaceID: authz.RoleOwner, testNamespaceID: authz.RoleOwner},
			uuidString(developerUUID): {sourceNamespaceID: authz.RoleOwner, testNamespaceID: authz.RoleDeveloper},
			uuidString(strangerUUID):  {sourceNamespaceID: authz.RoleOwner},
		},
	}
	tests := []struct {
		name       string
		exists     bool
		token      string
		wantStatus int
	}{
		{name: "owner of the target moves it", exists: true, token: "owner-token", wantStatus: http.StatusOK},
		{name: "member without manage_source gets 403", exists: true, token: "developer-token", wantStatus: http.StatusForbidden},
		{name: "non-member of the target gets 404", exists: true, token: "stranger-token", wantStatus: http.StatusNotFound},
		{name: "missing namespace is 404, never created", exists: false, token: "owner-token", wantStatus: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			regSvc := &movingRegistryService{fakeRegistryService: fakeRegistryService{
				registry: service.Registry{ID: "r1", Name: "r", NamespaceID: sourceNamespaceID},
			}}
			h := api.NewHandler(nil, nil, auth, regSvc, &namedNamespaceService{exists: tt.exists}, nil, nil, nil, nil, nil, &fakePinger{}, nil, &config.Config{})
			router := api.NewRouter(h, "*", "", "")

			w := memberRequest(router, http.MethodPatch, "/api/v1/registries/00000000-0000-0000-0000-000000000001", moveRegistryBody, tt.token)

			is.Equal(w.Code, tt.wantStatus)
			if tt.wantStatus == http.StatusOK {
				is.Equal(regSvc.moved, []string{"r1→" + testNamespaceID})
			} else {
				is.Equal(len(regSvc.moved), 0)
			}
		})
	}
}
