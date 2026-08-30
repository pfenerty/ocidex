// Package authz holds the capability model: what a namespace role may do.
//
// It is deliberately its own package rather than part of internal/api. The
// operation-level half of authorization (the middlewares) lives in the API
// layer, but the row-level half runs in internal/service, and both need to ask
// the same question of the same table. A capability model that lived in
// internal/api would force the service layer to either import upward or keep a
// second copy — and a second copy of an authorization table is the shape of a
// privilege bug. Nothing here imports internal/api or internal/service, which
// TestPackageHasNoInternalImports enforces.
package authz

// Capability is one thing a member may do inside a namespace. Capabilities are
// the unit authorization is expressed in: an operation declares the capability
// it needs, and a role either grants it or does not. Roles never appear in an
// operation's declaration, so adding a role cannot silently widen an existing
// endpoint.
type Capability string

const (
	// CapReadPrivate reads namespace content that is not public — SBOMs,
	// artifacts, components, findings. Every role holds it: membership of a
	// private namespace is precisely the right to read it.
	CapReadPrivate Capability = "read_private"

	// CapIngest submits new SBOMs to the namespace, by upload or by API key.
	CapIngest Capability = "ingest"

	// CapTriggerScan re-runs discovery or scanning over what is already there.
	// It creates no new content and reveals nothing a reader cannot already
	// see, which is why security holds it and ingest is separate: confirming a
	// fix must not require the right to publish.
	CapTriggerScan Capability = "trigger_scan"

	// CapPushInventory reports cluster workloads into the namespace. It pairs
	// with CapIngest as the other thing CI does.
	CapPushInventory Capability = "push_inventory"

	// CapDeleteArtifact removes stored content. Destructive and irreversible,
	// so it stops at maintainer.
	CapDeleteArtifact Capability = "delete_artifact"

	// CapManageSource creates, reconfigures, or removes the namespace's ingest
	// sources and registries.
	CapManageSource Capability = "manage_source"

	// CapManageCluster registers or removes the clusters bound to the
	// namespace.
	CapManageCluster Capability = "manage_cluster"

	// CapReadSecret reads a stored credential back out — a registry password,
	// a webhook secret. It is the capability that separates security from
	// maintainer: a security member reads everything the namespace knows and
	// may re-scan to confirm a fix, but cannot walk away with the credentials
	// the namespace uses to reach a registry.
	CapReadSecret Capability = "read_secret"

	// CapManageMember adds, removes, or re-roles members. Owner only: the
	// right to grant rights is not a right maintainers have.
	CapManageMember Capability = "manage_member"

	// CapDeleteNamespace destroys the namespace and everything under it. Owner
	// only, for the same reason.
	CapDeleteNamespace Capability = "delete_namespace"
)

// Role is a member's role within one namespace. It is not the installation-wide
// role on ocidex_user.role, which is a different axis: the global role decides
// whether you may use the installation at all, the namespace role decides what
// you may do inside a namespace you belong to.
//
// The set is closed and mirrors the CHECK constraint on namespace_member.role.
// Roles are not data: a new role is a code change, because a role without a
// capability set grants nothing and a database-defined one could never have
// one.
type Role string

const (
	// RoleOwner holds every capability. Exactly one per namespace, enforced by
	// the namespace_one_owner index rather than by convention.
	RoleOwner Role = "owner"

	// RoleMaintainer runs the namespace day to day — everything except
	// granting rights and destroying the namespace.
	RoleMaintainer Role = "maintainer"

	// RoleSecurity reads everything and may re-scan, but cannot publish and
	// cannot read a credential.
	RoleSecurity Role = "security"

	// RoleDeveloper does what CI does: read, ingest, push inventory, re-scan.
	// It cannot reconfigure a source or read a secret.
	RoleDeveloper Role = "developer"

	// RoleViewer reads, and nothing more.
	RoleViewer Role = "viewer"
)

// Installation-wide roles on ocidex_user.role, repeated here because Allow
// needs them and this package may not import internal/service. The strings are
// the same values; a divergence would show up as a global admin losing their
// short-circuit, which TestGlobalRoleStringsMatchTheDatabase guards.
const (
	globalRoleAdmin  = "admin"
	globalRoleViewer = "viewer"
)

// allRoles and allCapabilities are the enumerations the exhaustiveness test
// walks. They are the reason adding a constant without deciding its answer
// fails the build: a new Capability with no roleCaps entry is a missing cell,
// not an implicit deny.
var allRoles = []Role{RoleOwner, RoleMaintainer, RoleSecurity, RoleDeveloper, RoleViewer}

var allCapabilities = []Capability{
	CapReadPrivate,
	CapIngest,
	CapTriggerScan,
	CapPushInventory,
	CapDeleteArtifact,
	CapManageSource,
	CapManageCluster,
	CapReadSecret,
	CapManageMember,
	CapDeleteNamespace,
}

// roleCaps is the authorization table. Every role names every capability
// explicitly, including the ones it does not hold, so that a false is a
// decision somebody made and not an entry somebody forgot. That is what makes
// TestEveryRoleDeclaresEveryCapability a real guard rather than a spelling
// check.
//
// It is unexported on purpose. Callers ask Role.Allows or Allow; nobody gets to
// read the table and reimplement the lookup, which is how the two halves of the
// authorization model drift apart.
var roleCaps = map[Role]map[Capability]bool{
	RoleOwner: {
		CapReadPrivate:     true,
		CapIngest:          true,
		CapTriggerScan:     true,
		CapPushInventory:   true,
		CapDeleteArtifact:  true,
		CapManageSource:    true,
		CapManageCluster:   true,
		CapReadSecret:      true,
		CapManageMember:    true,
		CapDeleteNamespace: true,
	},
	RoleMaintainer: {
		CapReadPrivate:     true,
		CapIngest:          true,
		CapTriggerScan:     true,
		CapPushInventory:   true,
		CapDeleteArtifact:  true,
		CapManageSource:    true,
		CapManageCluster:   true,
		CapReadSecret:      true,
		CapManageMember:    false,
		CapDeleteNamespace: false,
	},
	RoleSecurity: {
		CapReadPrivate:     true,
		CapIngest:          false,
		CapTriggerScan:     true,
		CapPushInventory:   false,
		CapDeleteArtifact:  false,
		CapManageSource:    false,
		CapManageCluster:   false,
		CapReadSecret:      false,
		CapManageMember:    false,
		CapDeleteNamespace: false,
	},
	RoleDeveloper: {
		CapReadPrivate:     true,
		CapIngest:          true,
		CapTriggerScan:     true,
		CapPushInventory:   true,
		CapDeleteArtifact:  false,
		CapManageSource:    false,
		CapManageCluster:   false,
		CapReadSecret:      false,
		CapManageMember:    false,
		CapDeleteNamespace: false,
	},
	RoleViewer: {
		CapReadPrivate:     true,
		CapIngest:          false,
		CapTriggerScan:     false,
		CapPushInventory:   false,
		CapDeleteArtifact:  false,
		CapManageSource:    false,
		CapManageCluster:   false,
		CapReadSecret:      false,
		CapManageMember:    false,
		CapDeleteNamespace: false,
	},
}

// Allows reports whether the namespace role r grants c. An unknown role grants
// nothing, so a role string read from a row written by a future version denies
// rather than panics.
func (r Role) Allows(c Capability) bool {
	return roleCaps[r][c]
}

// Valid reports whether r is one of the five known roles. Use it to reject a
// role at the API boundary; the database CHECK is the backstop, not the
// message.
func (r Role) Valid() bool {
	_, ok := roleCaps[r]
	return ok
}

// Capabilities returns the capabilities r grants, in declaration order. It
// exists for rendering — telling a member what their role means — and returns a
// fresh slice each call so a caller cannot edit the table through it.
func (r Role) Capabilities() []Capability {
	caps := roleCaps[r]
	out := make([]Capability, 0, len(caps))
	for _, c := range allCapabilities {
		if caps[c] {
			out = append(out, c)
		}
	}
	return out
}

// Dominates reports whether r grants every capability other grants. It is the
// question member management asks before writing a grant: a member may hand out
// a role only if they already hold everything that role would confer, so nobody
// grants themselves a promotion by way of a colleague.
//
// It is deliberately a capability-set comparison rather than a rank. The five
// roles are not a chain — security and developer each hold something the other
// does not — so any total ordering would have to invent an answer for pairs the
// capability table already answers. A role always dominates itself, and an
// unknown role holds nothing, so it dominates only other empty roles.
func (r Role) Dominates(other Role) bool {
	mine := roleCaps[r]
	for c, held := range roleCaps[other] {
		if held && !mine[c] {
			return false
		}
	}
	return true
}

// AllRoles returns the five roles, highest first. Fresh slice per call.
func AllRoles() []Role {
	return append([]Role(nil), allRoles...)
}

// AllCapabilities returns every capability, in declaration order. Fresh slice
// per call.
func AllCapabilities() []Capability {
	return append([]Capability(nil), allCapabilities...)
}

// Allow answers the whole question for one caller and one namespace: does a
// principal with installation-wide role globalRole, holding namespace role
// member (present reports whether they are a member at all), have c?
//
// The two global rules live here rather than at each call site, because they
// are the ones that are easy to get half-right:
//
//   - A global admin short-circuits every capability check. Admin is an
//     installation-wide override and always has been; membership does not
//     constrain it.
//   - A global viewer is the floor. Namespace membership grants such a
//     principal nothing beyond reading, whatever role a namespace owner gave
//     them — an installation that has decided somebody is read-only must not
//     have that reversed by a namespace they were invited into.
//
// A non-member gets nothing. Public-namespace reads do not come through here:
// they are answered by the visibility functions in SQL, which is why
// CapReadPrivate is named for the private case.
func Allow(globalRole string, member Role, present bool, c Capability) bool {
	if globalRole == globalRoleAdmin {
		return true
	}
	if !present {
		return false
	}
	if globalRole == globalRoleViewer {
		return c == CapReadPrivate && member.Allows(c)
	}
	return member.Allows(c)
}

// RolesWith returns the roles that grant c, as plain strings, for handing to
// the SQL function namespace_ids_with_capability. It is the only place a
// capability is resolved to a role set, which is what keeps roleCaps the single
// authorization table: the database filters rows by a role list it is given and
// holds no capability table of its own, so there is nothing on that side to
// drift.
//
// The result is ordered as allRoles is, so a query plan and a test fixture both
// see a stable array. An unknown capability yields an empty slice, which filters
// to no namespaces — deny, not allow.
func RolesWith(c Capability) []string {
	out := make([]string, 0, len(allRoles))
	for _, r := range allRoles {
		if r.Allows(c) {
			out = append(out, string(r))
		}
	}
	return out
}
