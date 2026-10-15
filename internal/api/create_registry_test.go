package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/service"
)

// namedNamespaceService is fakeNamespaceService where GetByName finds the
// namespace only once exists is set, so a test can choose between "new name"
// and "someone else's namespace".
type namedNamespaceService struct {
	fakeNamespaceService
	exists bool
}

func (n *namedNamespaceService) GetByName(ctx context.Context, name string) (service.Namespace, error) {
	if !n.exists {
		return service.Namespace{}, service.ErrNotFound
	}
	return n.fakeNamespaceService.GetByName(ctx, name)
}

// recordingRegistryService records every Create and answers with errs in order,
// then success.
type recordingRegistryService struct {
	fakeRegistryService
	calls []service.CreateRegistryParams
	errs  []error
	onErr func()
}

func (r *recordingRegistryService) Create(_ context.Context, p service.CreateRegistryParams) (service.Registry, error) {
	r.calls = append(r.calls, p)
	if len(r.errs) > 0 {
		err := r.errs[0]
		r.errs = r.errs[1:]
		if r.onErr != nil {
			r.onErr()
		}
		return service.Registry{}, err
	}
	return service.Registry{ID: "r1", Name: p.Name, NamespaceID: p.NamespaceID}, nil
}

const createRegistryInNamespace = `{"name":"r","type":"generic","url":"registry.example.com","insecure":false,"namespace":"test-ns","scan_mode":"webhook","repositories":[],"repository_patterns":[],"tag_patterns":[]}`

var (
	developerUUID = pgtype.UUID{Bytes: [16]byte{0xd0}, Valid: true}
	strangerUUID  = pgtype.UUID{Bytes: [16]byte{0x5e}, Valid: true}
	adminUUID     = pgtype.UUID{Bytes: [16]byte{0xad}, Valid: true}
)

func createRegistryRouter(nsSvc service.NamespaceService, regSvc service.RegistryService) http.Handler {
	allCaps := authz.AllCapabilities()
	authSvc := &fakeAuthService{
		users: map[string]service.AuthUser{
			"owner-token":     {ID: ownerUUID, Role: "member", APIKeyAuth: true, APIKeyCaps: allCaps},
			"developer-token": {ID: developerUUID, Role: "member", APIKeyAuth: true, APIKeyCaps: allCaps},
			"stranger-token":  {ID: strangerUUID, Role: "member", APIKeyAuth: true, APIKeyCaps: allCaps},
			"admin-token":     {ID: adminUUID, Role: "admin", APIKeyAuth: true, APIKeyCaps: allCaps},
		},
		grants: map[string]map[string]authz.Role{
			uuidString(ownerUUID):     {testNamespaceID: authz.RoleOwner},
			uuidString(developerUUID): {testNamespaceID: authz.RoleDeveloper},
		},
	}
	h := api.NewHandler(nil, nil, authSvc, regSvc, nsSvc, nil, nil, nil, nil, nil, &fakePinger{}, nil, &config.Config{})
	return api.NewRouter(h, "*", "", "")
}

// TestCreateRegistry_ExistingNamespaceAuthz covers ocidex-avsz.2: naming a
// namespace that exists requires manage_source in it.
func TestCreateRegistry_ExistingNamespaceAuthz(t *testing.T) {
	tests := []struct {
		name       string
		exists     bool
		token      string
		wantStatus int
		wantNSID   string
	}{
		{name: "new name is created", exists: false, token: "stranger-token", wantStatus: http.StatusCreated},
		{name: "owner of existing namespace", exists: true, token: "owner-token", wantStatus: http.StatusCreated, wantNSID: testNamespaceID},
		{name: "admin into existing namespace", exists: true, token: "admin-token", wantStatus: http.StatusCreated, wantNSID: testNamespaceID},
		{name: "non-member gets 404", exists: true, token: "stranger-token", wantStatus: http.StatusNotFound},
		{name: "member without manage_source gets 403", exists: true, token: "developer-token", wantStatus: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			regSvc := &recordingRegistryService{}
			router := createRegistryRouter(&namedNamespaceService{exists: tt.exists}, regSvc)

			w := memberRequest(router, http.MethodPost, "/api/v1/registries", createRegistryInNamespace, tt.token)

			is.Equal(w.Code, tt.wantStatus)
			if tt.wantStatus != http.StatusCreated {
				is.Equal(len(regSvc.calls), 0) // no registry written
				return
			}
			is.Equal(len(regSvc.calls), 1)
			is.Equal(regSvc.calls[0].NamespaceID, tt.wantNSID)
		})
	}
}

// TestCreateRegistry_NamespaceRaceRechecks: a namespace created by someone else
// between the lookup and the insert is authorized like any existing one, not
// attached unchecked.
func TestCreateRegistry_NamespaceRaceRechecks(t *testing.T) {
	is := is.New(t)
	nsSvc := &namedNamespaceService{}
	regSvc := &recordingRegistryService{errs: []error{service.ErrNamespaceExists}}
	regSvc.onErr = func() { nsSvc.exists = true }
	router := createRegistryRouter(nsSvc, regSvc)

	w := memberRequest(router, http.MethodPost, "/api/v1/registries", createRegistryInNamespace, "stranger-token")

	is.Equal(w.Code, http.StatusNotFound)
	is.Equal(len(regSvc.calls), 1)
}
