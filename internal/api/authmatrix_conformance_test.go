package api_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/authz"
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
// the moment it declares a class — except ClassCapability, whose rows need one
// hand-recorded fact each (see capProbes) and fail the build until they have
// one.
//
// "Admit" is "not 401 and not 403", not "200". The fakes behind
// newConformanceRouter answer with 204, 422 or 503 depending on the operation,
// and none of that is an authorization outcome. Asserting on the status code
// would make this a test of the fixtures.

// A persona is one seeded principal. The five mirror scripts/dev-auth.sh's
// PERSONAS array, and the two facts that matter to authorization are its global
// role and what it holds in the namespaces the fakes resolve to.
type persona struct {
	name  string
	token string
	user  service.AuthUser
}

// personas is the roster. Each carries a global role and, for the three that
// are members of the fixture namespaces, a namespace role (see personaRoles).
// The four member-ish personas are what let a capability be probed from both
// sides: devowner holds every capability, devsecurity holds only read_private
// and trigger_scan, devviewer is capped by its installation-wide viewer role
// whatever the namespace grants it, and devoutsider is a member of nothing.
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

// personaRoles is each persona's namespace role in the fixture. A persona
// absent from this map is a member of nothing — the "authenticated but
// unrelated" case every capability must refuse.
var personaRoles = map[string]authz.Role{
	"devowner":    authz.RoleOwner,
	"devsecurity": authz.RoleSecurity,
	"devviewer":   authz.RoleViewer,
}

// personaRole reports p's namespace role and whether p is a member at all —
// the two arguments authz.Allow takes.
func personaRole(p persona) (authz.Role, bool) {
	role, ok := personaRoles[p.name]
	return role, ok
}

// personaGrants is the membership the fake auth service hands back. The fakes
// resolve every namespaced route to one of two namespaces — testNamespaceID for
// namespaces, sources and clusters, mwNamespaceID for registries — so each
// member holds the same role in both, which is what lets capabilityVerdict
// answer without knowing which of the two a given route landed on.
func personaGrants() map[string]map[string]authz.Role {
	grants := map[string]map[string]authz.Role{}
	for _, p := range personas {
		role, ok := personaRoles[p.name]
		if !ok {
			continue
		}
		grants[uuidString(p.user.ID)] = map[string]authz.Role{
			testNamespaceID: role,
			mwNamespaceID:   role,
		}
	}
	return grants
}

func personaAuthService() *fakeAuthService {
	users := map[string]service.AuthUser{
		readOnlyToken: {ID: personaID(0xa1), GitHubUsername: "devadmin", Role: "admin", APIKeyScope: "read"},
	}
	for _, p := range personas {
		users[p.token] = p.user
	}
	return &fakeAuthService{users: users, grants: personaGrants()}
}

// capProbe records what this fixture is actually able to observe about a
// ClassCapability operation. Not every capability rule is reachable from a
// table-driven probe, and recording which are not is the point: an operation
// silently in the wrong bucket is a rule nobody is checking.
type capProbe string

const (
	// capEnforced: the probe reaches the capability check and a member
	// without the capability is refused. This is the bucket that actually
	// proves the rule, and the only one
	// TestEveryEnforcedCapabilityIsProbedBothWays counts.
	capEnforced capProbe = "enforced"

	// capRequestGated: the target namespace is knowable only from the request
	// body or query, so the request is answered — 422 from huma for the
	// probe's `{}`, 400 from the handler for a missing `?source=` — before the
	// capability check runs. The rule is enforced in the handler and covered by
	// that handler's own tests; this harness cannot see it. RequireCapability
	// takes a resolver, so writing a body resolver would move these to
	// capEnforced.
	capRequestGated capProbe = "request-gated"

	// capNoNamespace: the fake resolves no namespace for the target, and
	// RequireCapability deliberately falls through to the member/admin floor
	// when the row hangs from none — the legacy arm that outlives the nullable
	// sbom.namespace_id. So the probe observes the floor, not the capability
	// rule.
	capNoNamespace capProbe = "no-namespace"
)

// capProbes must name every ClassCapability operation.
// TestCapProbesCoverEveryCapabilityOperation fails the build when one is
// missing, which is the same discipline TestAuthClassCoverage applies to
// authRules: a new capability-class operation may not slip in without someone
// deciding what this harness can prove about it.
var capProbes = map[string]capProbe{
	"delete-cluster":                capEnforced,
	"ingest-cluster-unknown-images": capEnforced,
	"delete-namespace":              capEnforced,
	"update-namespace":              capEnforced,
	"delete-registry":               capEnforced,
	"update-registry":               capEnforced,
	"scan-registry":                 capEnforced,
	"regenerate-webhook-secret":     capEnforced,
	"delete-source":                 capEnforced,
	"list-namespace-members":        capEnforced,
	"set-namespace-member":          capEnforced,
	"remove-namespace-member":       capEnforced,

	"create-cluster":        capRequestGated,
	"update-cluster":        capRequestGated,
	"put-cluster-inventory": capRequestGated,
	"create-source":         capRequestGated,
	"update-source":         capRequestGated,

	"ingest-sbom": capRequestGated,

	"delete-artifact": capNoNamespace,
	"delete-sbom":     capNoNamespace,
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

// capabilityVerdict is what a declared capability promises one persona. It asks
// authz.Allow the same question the middleware does rather than restating the
// role table here, because a second copy of that table would happily agree with
// a wrong one in production. What this harness proves is the wiring: that the
// capability an operation declares is the one its route actually enforces.
func capabilityVerdict(c authz.Capability, p persona) verdict {
	role, present := personaRole(p)
	if authz.Allow(p.user.Role, role, present, c) {
		return admitted
	}
	return forbidden
}

// expectFor returns the verdict the declared class promises for one persona, and
// whether the harness is able to assert it at all.
func expectFor(r api.AuthMatrixRow, p persona) (verdict, bool) {
	isAdmin := p.user.Role == "admin"
	isMember := p.user.Role == "member"

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

	case api.ClassCapability:
		switch capProbes[r.OperationID] {
		case capEnforced:
			return capabilityVerdict(r.Rule.Cap, p), true
		case capNoNamespace:
			// The capability check falls through, but the member/admin floor
			// still holds and is worth pinning: it is what keeps a viewer out.
			if isAdmin || isMember {
				return admitted, true
			}
			return forbidden, true
		case capRequestGated:
			// The request is answered before the capability check, for every
			// persona.
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

// TestCapProbesCoverEveryCapabilityOperation is the build break the acceptance
// criteria ask for: a capability-class operation with no entry here has no
// persona expectation, and the suite says so instead of silently skipping it.
func TestCapProbesCoverEveryCapabilityOperation(t *testing.T) {
	registered := map[string]bool{}
	var missing []string
	for _, r := range conformanceSpec() {
		if !r.Declared || r.Rule.Class != api.ClassCapability {
			continue
		}
		registered[r.OperationID] = true
		if _, ok := capProbes[r.OperationID]; !ok {
			missing = append(missing, r.OperationID)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("capability-class operations with no entry in capProbes "+
			"(decide what this harness can prove about each):\n  %s",
			strings.Join(missing, "\n  "))
	}

	var stale []string
	for id := range capProbes {
		if !registered[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("capProbes names operations that are not capability-class any more:\n  %s",
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

// TestEveryEnforcedCapabilityIsProbedBothWays is what makes the roster mean
// something. A capability row driven only by principals that hold it proves the
// route is reachable, not that it is guarded; one driven only by principals that
// lack it would pass just as well if the handler were deleted. So every enforced
// row must have a persona this harness expects to admit and a persona it expects
// to refuse — and TestPersonaConformance then drives both.
func TestEveryEnforcedCapabilityIsProbedBothWays(t *testing.T) {
	var oneSided []string
	for _, r := range conformanceSpec() {
		if !r.Declared || r.Rule.Class != api.ClassCapability {
			continue
		}
		if capProbes[r.OperationID] != capEnforced {
			continue
		}
		var admits, refuses int
		for _, p := range personas {
			if capabilityVerdict(r.Rule.Cap, p) == admitted {
				admits++
			} else {
				refuses++
			}
		}
		if admits == 0 || refuses == 0 {
			oneSided = append(oneSided, fmt.Sprintf("%s (%s): %d admitted, %d refused",
				r.OperationID, r.Rule.Cap, admits, refuses))
		}
	}
	sort.Strings(oneSided)
	if len(oneSided) > 0 {
		t.Fatalf("capability operations no persona exercises from both sides "+
			"(give a persona in personaRoles a role that separates them):\n  %s",
			strings.Join(oneSided, "\n  "))
	}
}

// TestCapabilityIsDeclaredExactlyWhereItIsUsed pins the two halves of the rule
// together: a ClassCapability row without a Cap has nothing for the middleware
// to check, and a Cap on any other class is a capability nobody enforces.
func TestCapabilityIsDeclaredExactlyWhereItIsUsed(t *testing.T) {
	for _, r := range conformanceSpec() {
		if !r.Declared {
			continue
		}
		switch {
		case r.Rule.Class == api.ClassCapability && r.Rule.Cap == "":
			t.Errorf("%s declares %s but names no capability", r.OperationID, api.ClassCapability)
		case r.Rule.Class != api.ClassCapability && r.Rule.Cap != "":
			t.Errorf("%s is class %s but names capability %q; only %s is enforced by capability",
				r.OperationID, r.Rule.Class, r.Rule.Cap, api.ClassCapability)
		}
	}
}
