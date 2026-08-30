package api_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// memberTargetID is the user a grant is aimed at: someone other than the owner
// doing the granting.
const memberTargetID = "0f0e0d0c-0b0a-0908-0706-050403020100"

// conflictNamespaceService is fakeNamespaceService with the two refusals member
// management owes a caller, so the API tests can prove the status codes without
// a database. Everything else is inherited.
type conflictNamespaceService struct {
	fakeNamespaceService
	setErr    error
	removeErr error
}

func (c *conflictNamespaceService) SetMember(ctx context.Context, params service.SetNamespaceMemberParams) (service.NamespaceMember, error) {
	if c.setErr != nil {
		return service.NamespaceMember{}, c.setErr
	}
	return c.fakeNamespaceService.SetMember(ctx, params)
}

func (c *conflictNamespaceService) RemoveMember(ctx context.Context, namespaceID, userID string) error {
	if c.removeErr != nil {
		return c.removeErr
	}
	return c.fakeNamespaceService.RemoveMember(ctx, namespaceID, userID)
}

// memberRouter wires the namespace service under test behind an auth service
// where "owner-token" holds the given namespace role and every user named in
// usersByID exists.
func rosterRouter(nsSvc service.NamespaceService, role authz.Role) http.Handler {
	authSvc := &fakeAuthService{
		users: map[string]service.AuthUser{
			"owner-token": {ID: ownerUUID, Role: "member", APIKeyAuth: true, APIKeyCaps: authz.AllCapabilities()},
		},
		grants: map[string]map[string]authz.Role{
			uuidString(ownerUUID): {testNamespaceID: role},
		},
		usersByID: map[string]service.AuthUser{
			memberTargetID: {GitHubUsername: "devsecurity"},
			ownerIDStr:     {ID: ownerUUID, GitHubUsername: "devowner"},
		},
	}
	h := api.NewHandler(nil, nil, authSvc, nil, nsSvc, nil, nil, nil, nil, nil, &fakePinger{}, nil, nil)
	return api.NewRouter(h, "*", "", "")
}

func memberRequest(router http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func membersPath() string   { return "/api/v1/namespaces/" + testNamespaceID + "/members" }
func memberPath() string    { return membersPath() + "/" + memberTargetID }
func ownerSeatPath() string { return membersPath() + "/" + ownerIDStr }

// TestListNamespaceMembersRequiresManageMember pins who may read the roster.
// Seeing who holds which role is the same privilege as changing it: a viewer
// who could enumerate the members would be reading the namespace's org chart.
func TestListNamespaceMembersRequiresManageMember(t *testing.T) {
	is := is.New(t)

	is.Equal(memberRequest(rosterRouter(&fakeNamespaceService{}, authz.RoleOwner),
		http.MethodGet, membersPath(), "", "owner-token").Code, http.StatusOK)

	is.Equal(memberRequest(rosterRouter(&fakeNamespaceService{}, authz.RoleMaintainer),
		http.MethodGet, membersPath(), "", "owner-token").Code, http.StatusForbidden)

	is.Equal(memberRequest(rosterRouter(&fakeNamespaceService{}, authz.RoleOwner),
		http.MethodGet, membersPath(), "", "").Code, http.StatusUnauthorized)
}

// TestSetNamespaceMemberGrantsARole is the ordinary case: an owner hands a role
// to a user who exists, and gets the resulting membership back.
func TestSetNamespaceMemberGrantsARole(t *testing.T) {
	is := is.New(t)

	w := memberRequest(rosterRouter(&fakeNamespaceService{}, authz.RoleOwner),
		http.MethodPut, memberPath(), `{"role":"security"}`, "owner-token")
	is.Equal(w.Code, http.StatusOK)

	body := w.Body.String()
	is.True(bytes.Contains([]byte(body), []byte(`"role":"security"`)))
	is.True(bytes.Contains([]byte(body), []byte(`"username":"devsecurity"`)))
	// The capabilities the role confers are projected for display, so the UI
	// does not have to keep a second copy of the role table.
	is.True(bytes.Contains([]byte(body), []byte(`"trigger_scan"`)))
}

// TestSetNamespaceMemberUnknownUserIs404 states the absence of an invite flow:
// a member is somebody who has already signed in, and granting a role to a UUID
// that is nobody is a mistake rather than a pending invitation.
func TestSetNamespaceMemberUnknownUserIs404(t *testing.T) {
	is := is.New(t)

	w := memberRequest(rosterRouter(&fakeNamespaceService{}, authz.RoleOwner),
		http.MethodPut, membersPath()+"/00000000-0000-0000-0000-0000000000aa",
		`{"role":"viewer"}`, "owner-token")
	is.Equal(w.Code, http.StatusNotFound)
}

// TestSetNamespaceMemberRejectsUnknownRole leans on the enum in the schema:
// the closed role set is a validation error at the edge, not a database CHECK
// violation four layers in.
func TestSetNamespaceMemberRejectsUnknownRole(t *testing.T) {
	is := is.New(t)

	w := memberRequest(rosterRouter(&fakeNamespaceService{}, authz.RoleOwner),
		http.MethodPut, memberPath(), `{"role":"superuser"}`, "owner-token")
	is.Equal(w.Code, http.StatusUnprocessableEntity)
}

// TestMemberConflictsAre409 covers the two refusals that protect the last
// owner. Both reach the API as service.ErrConflict, and both must arrive at the
// caller as 409 rather than as a 500 with a constraint name in the log.
func TestMemberConflictsAre409(t *testing.T) {
	is := is.New(t)

	demote := &conflictNamespaceService{setErr: service.ErrConflict}
	is.Equal(memberRequest(rosterRouter(demote, authz.RoleOwner),
		http.MethodPut, ownerSeatPath(), `{"role":"maintainer"}`, "owner-token").Code,
		http.StatusConflict)

	remove := &conflictNamespaceService{removeErr: service.ErrConflict}
	is.Equal(memberRequest(rosterRouter(remove, authz.RoleOwner),
		http.MethodDelete, ownerSeatPath(), "", "owner-token").Code,
		http.StatusConflict)
}

// TestRemoveNamespaceMemberIs204 is the ordinary removal.
func TestRemoveNamespaceMemberIs204(t *testing.T) {
	is := is.New(t)

	is.Equal(memberRequest(rosterRouter(&fakeNamespaceService{}, authz.RoleOwner),
		http.MethodDelete, memberPath(), "", "owner-token").Code, http.StatusNoContent)
}
