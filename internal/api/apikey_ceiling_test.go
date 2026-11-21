package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// An API key's capabilities are a ceiling, so a key may only create or delete
// keys within that ceiling, and may not link a sign-in identity at all.

const (
	tokenScanKey = "scan-key" // a CI key holding trigger_scan only
	tokenFullKey = "full-key" // a key holding every capability
)

var (
	ceilingUser = personaID(0xc1)
	wideKeyID   = personaID(0xd1) // a key holding every capability
	scanKeyID   = personaID(0xd2) // a key holding trigger_scan only
)

// keyMgmtAuthService records the key operations that got past the API layer.
type keyMgmtAuthService struct {
	fakeAuthService
	created [][]authz.Capability
	deleted []string
}

func (f *keyMgmtAuthService) CreateExpiringAPIKey(_ context.Context, _ string, _ string, caps []authz.Capability, _ time.Time) (string, error) {
	f.created = append(f.created, caps)
	return "ocidex_new", nil
}

func (f *keyMgmtAuthService) ListAPIKeys(_ context.Context, _ string) ([]service.APIKeyMeta, error) {
	return []service.APIKeyMeta{
		{ID: wideKeyID.String(), Capabilities: authz.AllCapabilities()},
		{ID: scanKeyID.String(), Capabilities: []authz.Capability{authz.CapTriggerScan}},
	}, nil
}

func (f *keyMgmtAuthService) DeleteAPIKey(_ context.Context, _ string, id string) error {
	f.deleted = append(f.deleted, id)
	return nil
}

func newKeyMgmtAuthService() *keyMgmtAuthService {
	return &keyMgmtAuthService{fakeAuthService: fakeAuthService{users: map[string]service.AuthUser{
		tokenScanKey: {ID: ceilingUser.String(), DisplayName: "ci", Role: "member", APIKeyAuth: true,
			APIKeyCaps: []authz.Capability{authz.CapTriggerScan}},
		tokenFullKey: {ID: ceilingUser.String(), DisplayName: "ci", Role: "member", APIKeyAuth: true,
			APIKeyCaps: authz.AllCapabilities()},
	}}}
}

func TestCreateAPIKeyIsBoundedByTheCallingKey(t *testing.T) {
	tests := []struct {
		name  string
		token string
		body  string
		want  int
	}{
		{"narrow key asks for a wider capability", tokenScanKey, `{"name":"x","capabilities":["read_secret"]}`, http.StatusForbidden},
		{"narrow key asks for everything (empty list)", tokenScanKey, `{"name":"x"}`, http.StatusForbidden},
		{"narrow key mixes its own and a wider capability", tokenScanKey, `{"name":"x","capabilities":["trigger_scan","delete_namespace"]}`, http.StatusForbidden},
		{"narrow key mints a subset of itself", tokenScanKey, `{"name":"x","capabilities":["trigger_scan"]}`, http.StatusCreated},
		{"full key mints everything", tokenFullKey, `{"name":"x"}`, http.StatusCreated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			svc := newKeyMgmtAuthService()
			rec := doAuthRequest(newAuthBoundaryRouter(svc), http.MethodPost, "/api/v1/auth/keys", tt.body, tt.token)
			is.Equal(rec.Code, tt.want)
			is.Equal(len(svc.created) == 1, tt.want == http.StatusCreated) // a refused request reached the service
		})
	}
}

func TestDeleteAPIKeyIsBoundedByTheCallingKey(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		target pgtype.UUID
		want   int
	}{
		{"narrow key revokes a wider key", tokenScanKey, wideKeyID, http.StatusForbidden},
		{"narrow key revokes an equal key", tokenScanKey, scanKeyID, http.StatusNoContent},
		{"full key revokes a wider key", tokenFullKey, wideKeyID, http.StatusNoContent},
		{"unknown key", tokenScanKey, personaID(0xee), http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			svc := newKeyMgmtAuthService()
			rec := doAuthRequest(newAuthBoundaryRouter(svc), http.MethodDelete,
				"/api/v1/auth/keys/"+tt.target.String(), "", tt.token)
			is.Equal(rec.Code, tt.want)
			is.Equal(len(svc.deleted) == 1, tt.want == http.StatusNoContent)
		})
	}
}

// Linking adds a sign-in to the account, and a sign-in carries no ceiling.
func TestLinkIdentityRefusesAPIKeys(t *testing.T) {
	is := is.New(t)
	svc := newLinkAuthService()
	svc.users = map[string]service.AuthUser{
		tokenFullKey: {ID: ceilingUser.String(), DisplayName: "ci", Role: "member", APIKeyAuth: true,
			APIKeyCaps: authz.AllCapabilities()},
	}
	req := doAuthRequest(newIdentityTestRouter(svc), http.MethodPost, "/api/v1/auth/identities",
		`{"provider":"github"}`, tokenFullKey)
	is.Equal(req.Code, http.StatusForbidden)
	is.True(strings.Contains(req.Body.String(), "signed-in session"))
}
