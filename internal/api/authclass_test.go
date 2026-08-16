package api_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/service"
)

// The authorization conformance suite. It holds two properties together:
//
//   - every operation registered on the router carries a declared auth class
//     (and no declaration outlives its operation), and
//   - the router actually enforces the class it declares.
//
// The second half is what makes the first half worth having: a declaration
// nobody enforces is documentation, not a control. Deleting the row from
// authRules fails TestAuthClassCoverage; deleting a role middleware from a
// registration fails TestMemberClassEnforced or TestAdminClassEnforced.
//
// One honest limit: TestAuthClassEnforced cannot distinguish a 401 raised by
// RequireAuthenticated from one raised by a handler's own defensive
// UserFromContext check. Handlers that need the principal to build a
// VisibilityFilter keep that check deliberately — an absent middleware must not
// degrade into an empty user and a silently public answer — so for those
// operations the probe confirms the rule holds, not where it is enforced.

// pathParam matches a huma path template segment, e.g. `{id}`.
var pathParam = regexp.MustCompile(`\{[^}]+\}`)

// conformanceUUID is substituted for every path parameter. Auth middlewares run
// before huma parses or validates input, so the value only has to be a single
// non-empty path segment that chi will route.
const conformanceUUID = "00000000-0000-0000-0000-0000000000ff"

// newConformanceRouter builds a router with every service the auth middlewares
// consult wired to a fake. The registry service matters especially:
// RequireRegistryOwner degrades to a pass-through when its service is nil, so a
// router built with nil services would silently skip owner-class enforcement
// and the suite would pass while proving nothing.
func newConformanceRouter(authSvc service.AuthService) http.Handler {
	h := api.NewHandler(
		&fakeSBOMService{},
		nil,
		authSvc,
		&fakeRegistryService{registry: testRegistry},
		&fakeNamespaceService{},
		&fakeSourceService{},
		nil, nil, nil,
		&fakePinger{},
		nil, nil,
	)
	return api.NewRouter(h, "*", "", "")
}

// conformanceSpec returns the OpenAPI spec of a freshly built router, which is
// the authoritative list of registered operations.
func conformanceSpec() []api.AuthMatrixRow {
	h := api.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	_ = api.NewRouter(h, "*", "", "")
	return api.AuthMatrixRows(h.API().OpenAPI())
}

func requestPath(path string) string {
	return pathParam.ReplaceAllString(path, conformanceUUID)
}

func newConformanceRequest(method, path string) *http.Request {
	var body *strings.Reader
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		body = strings.NewReader("{}")
	default:
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, requestPath(path), body)
	r.Header.Set("Content-Type", "application/json")
	return r
}

// TestAuthClassCoverage fails if a registered operation has no declaration, or
// if a declaration names an operation that is no longer registered. Adding a
// handler without deciding who may call it is the failure mode this catches.
func TestAuthClassCoverage(t *testing.T) {
	is := is.New(t)

	rows := conformanceSpec()
	is.True(len(rows) > 0) // spec produced no operations

	var undeclared []string
	registered := map[string]bool{}
	for _, r := range rows {
		registered[r.OperationID] = true
		if !r.Declared {
			undeclared = append(undeclared, r.Method+" "+r.Path+" ("+r.OperationID+")")
		}
	}
	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		t.Fatalf("operations registered with no auth class in internal/api/authclass.go:\n  %s",
			strings.Join(undeclared, "\n  "))
	}

	var orphaned []string
	for id := range api.AuthRules() {
		if !registered[id] {
			orphaned = append(orphaned, id)
		}
	}
	sort.Strings(orphaned)
	if len(orphaned) > 0 {
		t.Fatalf("auth class declared for operations that are no longer registered:\n  %s",
			strings.Join(orphaned, "\n  "))
	}
}

// TestWriteScopeDeclaredForMutations pins the invariant that write scope tracks
// the HTTP method: every state-mutating operation declares RequireWrite, and no
// read-only one does. Without it a new POST could quietly accept a read-scoped
// API key.
func TestWriteScopeDeclaredForMutations(t *testing.T) {
	for _, r := range conformanceSpec() {
		if !r.Declared || r.Rule.Class == api.ClassSecret {
			continue
		}
		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		switch {
		case mutating && !r.Rule.Write:
			t.Errorf("%s %s (%s) mutates state but does not declare Write", r.Method, r.Path, r.OperationID)
		case !mutating && r.Rule.Write:
			t.Errorf("%s %s (%s) declares Write but does not mutate state", r.Method, r.Path, r.OperationID)
		}
	}
}

// TestAuthClassEnforced is the behavioural half: an unauthenticated request to
// any operation whose class requires an identity must be rejected by the router
// with 401, and a public one must not be. This is what fails when a middleware
// is dropped from a registration in router.go.
func TestAuthClassEnforced(t *testing.T) {
	router := newConformanceRouter(&fakeAuthService{users: map[string]service.AuthUser{}})

	for _, r := range conformanceSpec() {
		if !r.Declared || r.Rule.Class == api.ClassSecret {
			// A secret-class operation authenticates on a shared secret in the
			// request, so "no credentials" is not a meaningful probe.
			continue
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, newConformanceRequest(r.Method, r.Path))

		if r.Rule.Class == api.ClassPublic {
			if w.Code == http.StatusUnauthorized {
				t.Errorf("%s %s (%s) is declared %s but rejected an anonymous caller with 401",
					r.Method, r.Path, r.OperationID, r.Rule.Class)
			}
			continue
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s (%s) is declared %s but returned %d to an anonymous caller, want 401",
				r.Method, r.Path, r.OperationID, r.Rule.Class, w.Code)
		}
	}
}

// TestMemberClassEnforced checks that a viewer — authenticated, but the lowest
// role — is refused every member-class operation.
func TestMemberClassEnforced(t *testing.T) {
	router := newConformanceRouter(&fakeAuthService{
		users: map[string]service.AuthUser{
			"viewer-token": {ID: otherUUID, Role: "viewer"},
		},
	})

	for _, r := range conformanceSpec() {
		if !r.Declared || r.Rule.Class != api.ClassMember {
			continue
		}
		req := newConformanceRequest(r.Method, r.Path)
		req.Header.Set("Authorization", "Bearer viewer-token")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s (%s) is declared member but returned %d to a viewer, want 403",
				r.Method, r.Path, r.OperationID, w.Code)
		}
	}
}

// TestAdminClassEnforced checks the other end of the ladder: a fully
// authenticated, write-scoped member is still refused every admin-class
// operation.
func TestAdminClassEnforced(t *testing.T) {
	router := newConformanceRouter(&fakeAuthService{
		users: map[string]service.AuthUser{
			"member-token": {ID: otherUUID, Role: "member"},
		},
	})

	for _, r := range conformanceSpec() {
		if !r.Declared || r.Rule.Class != api.ClassAdmin {
			continue
		}
		req := newConformanceRequest(r.Method, r.Path)
		req.Header.Set("Authorization", "Bearer member-token")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s (%s) is declared admin but returned %d to a member, want 403",
				r.Method, r.Path, r.OperationID, w.Code)
		}
	}
}
