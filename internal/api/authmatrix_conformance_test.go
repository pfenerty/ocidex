package api_test

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/service"
)

// The role × operation conformance harness.
//
// authclass_test.go proves that a declared class is enforced *at all*: it
// probes the anonymous caller, and one wrong-role caller for member and admin.
// That catches a middleware deleted from a registration. It does not catch a
// class that admits one principal too many, because nothing drives the
// operation as every principal.
//
// This file does. It runs the five personas the dev rig seeds
// (scripts/dev-auth.sh) against every declared operation and asserts admit or
// deny against what the class promises. The expectations are derived from the
// class rather than written per operation, so a new operation inherits its row
// the moment it declares a class — except ClassOwner, whose rows need one
// hand-recorded fact each (see ownerProbes) and fail the build until they have
// one.
//
// "Admit" is "not 401 and not 403", not "200". The fakes behind
// newConformanceRouter answer with 204, 422 or 503 depending on the operation,
// and none of that is an authorization outcome. Asserting on the status code
// would make this a test of the fixtures.

// A persona is one seeded principal. The five mirror scripts/dev-auth.sh's
// PERSONAS array, and the two facts that matter to authorization are its global
// role and whether it owns the resources the fakes resolve to.
type persona struct {
	name  string
	token string
	user  service.AuthUser
}

// personas is the roster. devowner carries ownerUUID, which is the owner of
// every namespace and registry the fakes in helpers_test.go / middleware_test.go
// return, so it is the only principal that passes an ownership check without
// being an admin. devsecurity and devoutsider are deliberately two distinct
// non-owning members: the rig separates them because ocidex-y0hg will give them
// different capabilities in the same namespace, and the harness should already
// be driving both by then.
var personas = []persona{
	{name: "devadmin", token: "tok-devadmin",
		user: service.AuthUser{ID: personaID(0xa1), GitHubUsername: "devadmin", Role: "admin", APIKeyScope: "read-write"}},
	{name: "devowner", token: "tok-devowner",
		user: service.AuthUser{ID: ownerUUID, GitHubUsername: "devowner", Role: "member", APIKeyScope: "read-write"}},
	{name: "devsecurity", token: "tok-devsecurity",
		user: service.AuthUser{ID: personaID(0xa3), GitHubUsername: "devsecurity", Role: "member", APIKeyScope: "read-write"}},
	{name: "devviewer", token: "tok-devviewer",
		user: service.AuthUser{ID: personaID(0xa4), GitHubUsername: "devviewer", Role: "viewer", APIKeyScope: "read-write"}},
	{name: "devoutsider", token: "tok-devoutsider",
		user: service.AuthUser{ID: personaID(0xa5), GitHubUsername: "devoutsider", Role: "member", APIKeyScope: "read-write"}},
}

// readOnlyToken authenticates devadmin — the persona no class can refuse — with
// a read-scoped key, so a 403 on a Write operation can only have come from
// RequireWrite.
const readOnlyToken = "tok-readonly"

func personaAuthService() *fakeAuthService {
	users := map[string]service.AuthUser{
		readOnlyToken: {ID: personaID(0xa1), GitHubUsername: "devadmin", Role: "admin", APIKeyScope: "read"},
	}
	for _, p := range personas {
		users[p.token] = p.user
	}
	return &fakeAuthService{users: users}
}

// ownerProbe records what this fixture is actually able to observe about a
// ClassOwner operation. Not every owner-class rule is reachable from a
// table-driven probe, and recording which are not is the point: an operation
// silently in the wrong bucket is a rule nobody is checking.
type ownerProbe string

const (
	// ownerEnforced: the probe reaches the ownership check and a non-owning
	// member is refused. This is the bucket that actually proves the rule.
	ownerEnforced ownerProbe = "enforced"

	// ownerBodyGated: the target namespace is knowable only from the request
	// body, so huma rejects the conformance probe's `{}` with 422 before the
	// handler's canManageNamespace runs. The rule is enforced in the handler
	// and covered by that handler's own tests; this harness cannot see it.
	// ocidex-y0hg.5's RequireCapability moves the check into a middleware with
	// a path/body resolver, at which point these become ownerEnforced.
	ownerBodyGated ownerProbe = "body-gated"

	// ownerNoNamespace: the fake resolves no owning namespace for the target,
	// and Require{SBOM,Artifact}Owner deliberately fall through to the
	// member/admin floor when an SBOM has no namespace association. So the
	// probe observes the floor, not the ownership rule.
	ownerNoNamespace ownerProbe = "no-namespace"
)

// ownerProbes must name every ClassOwner operation.
// TestOwnerProbesCoverEveryOwnerOperation fails the build when one is missing,
// which is the same discipline TestAuthClassCoverage applies to authRules: a
// new owner-class operation may not slip in without someone deciding what this
// harness can prove about it.
var ownerProbes = map[string]ownerProbe{
	"delete-cluster":                ownerEnforced,
	"ingest-cluster-unknown-images": ownerEnforced,
	"delete-namespace":              ownerEnforced,
	"update-namespace":              ownerEnforced,
	"delete-registry":               ownerEnforced,
	"update-registry":               ownerEnforced,
	"scan-registry":                 ownerEnforced,
	"regenerate-webhook-secret":     ownerEnforced,
	"delete-source":                 ownerEnforced,

	"create-cluster":        ownerBodyGated,
	"update-cluster":        ownerBodyGated,
	"put-cluster-inventory": ownerBodyGated,
	"create-source":         ownerBodyGated,
	"update-source":         ownerBodyGated,

	"delete-artifact": ownerNoNamespace,
	"delete-sbom":     ownerNoNamespace,
}

// verdict is what a persona's probe of one operation produced, reduced to the
// only three outcomes authorization has.
type verdict string

const (
	admitted     verdict = "admitted"
	unauthorized verdict = "401"
	forbidden    verdict = "403"
)

func probe(router http.Handler, r api.AuthMatrixRow, token string) verdict {
	req := newConformanceRequest(r.Method, r.Path)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	switch w.Code {
	case http.StatusUnauthorized:
		return unauthorized
	case http.StatusForbidden:
		return forbidden
	default:
		return admitted
	}
}

// expectFor returns the verdict the declared class promises for one persona, and
// whether the harness is able to assert it at all.
func expectFor(r api.AuthMatrixRow, p persona) (verdict, bool) {
	isAdmin := p.user.Role == "admin"
	isMember := p.user.Role == "member"
	isOwner := p.user.ID == ownerUUID

	switch r.Rule.Class {
	case api.ClassPublic, api.ClassAuthenticated:
		return admitted, true

	case api.ClassMember:
		if isAdmin || isMember {
			return admitted, true
		}
		return forbidden, true

	case api.ClassAdmin:
		if isAdmin {
			return admitted, true
		}
		return forbidden, true

	case api.ClassOwner:
		switch ownerProbes[r.OperationID] {
		case ownerEnforced:
			if isAdmin || isOwner {
				return admitted, true
			}
			return forbidden, true
		case ownerNoNamespace:
			// The ownership check falls through, but the member/admin floor
			// still holds and is worth pinning: it is what keeps a viewer out.
			if isAdmin || isMember {
				return admitted, true
			}
			return forbidden, true
		case ownerBodyGated:
			// Validation answers first, for every persona.
			return "", false
		}
		return "", false

	case api.ClassSecret:
		// Authenticated by a shared secret in the request; a user identity is
		// never attached, so no persona probe is meaningful.
		return "", false
	}
	return "", false
}

// TestPersonaConformance is the harness. Every declared operation, every
// persona, admit or deny against the declared class.
func TestPersonaConformance(t *testing.T) {
	router := newConformanceRouter(personaAuthService())

	for _, r := range conformanceSpec() {
		if !r.Declared {
			continue
		}
		for _, p := range personas {
			want, assertable := expectFor(r, p)
			if !assertable {
				continue
			}
			got := probe(router, r, p.token)
			if got != want {
				t.Errorf("%s %s (%s, class %s): %s (%s) got %s, want %s",
					r.Method, r.Path, r.OperationID, r.Rule.Class,
					p.name, p.user.Role, got, want)
			}
		}
	}
}

// TestOwnerProbesCoverEveryOwnerOperation is the build break the acceptance
// criteria ask for: an owner-class operation with no entry here has no persona
// expectation, and the suite says so instead of silently skipping it.
func TestOwnerProbesCoverEveryOwnerOperation(t *testing.T) {
	registered := map[string]bool{}
	var missing []string
	for _, r := range conformanceSpec() {
		if !r.Declared || r.Rule.Class != api.ClassOwner {
			continue
		}
		registered[r.OperationID] = true
		if _, ok := ownerProbes[r.OperationID]; !ok {
			missing = append(missing, r.OperationID)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("owner-class operations with no entry in ownerProbes "+
			"(decide what this harness can prove about each):\n  %s",
			strings.Join(missing, "\n  "))
	}

	var stale []string
	for id := range ownerProbes {
		if !registered[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("ownerProbes names operations that are not owner-class any more:\n  %s",
			strings.Join(stale, "\n  "))
	}
}

// TestWriteScopeEnforcedForEveryMutation is the other half of the ten-key
// roster. TestWriteScopeDeclaredForMutations proves every mutation *declares*
// Write; this proves the declaration is wired, by driving each one with a
// read-scoped key belonging to an admin — the principal no class refuses, so a
// 403 can only have come from RequireWrite.
func TestWriteScopeEnforcedForEveryMutation(t *testing.T) {
	router := newConformanceRouter(personaAuthService())

	for _, r := range conformanceSpec() {
		if !r.Declared || !r.Rule.Write || r.Rule.Class == api.ClassSecret {
			continue
		}
		if got := probe(router, r, readOnlyToken); got != forbidden {
			t.Errorf("%s %s (%s) declares Write but a read-scoped admin key got %s, want 403",
				r.Method, r.Path, r.OperationID, got)
		}
	}
}
