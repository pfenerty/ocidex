package api

import (
	"fmt"
	"sort"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/authz"
)

// AuthClass is the authorization class of an operation: the single rule that
// decides whether a caller may invoke it at all. Every registered operation
// declares exactly one, and TestAuthClassCoverage fails the build if one is
// missing, stale, or contradicted by the router's middleware wiring.
//
// The class is orthogonal to the credential's own ceiling. A key declares the
// capabilities it may exercise (ADR-046); AuthRule.Write, which corresponds to
// RequireWrite in the router, records only whether the operation mutates at
// all. A mutating operation declares a class *and* Write, never Write alone.
type AuthClass string

const (
	// ClassPublic requires no credentials. Rows the caller may not see are
	// removed by a service.VisibilityFilter in SQL rather than by a 403, so an
	// anonymous caller gets a well-formed but narrower answer.
	ClassPublic AuthClass = "public"

	// ClassSecret is authenticated by a per-resource shared secret carried in
	// the request (a registry webhook HMAC), not by a user identity. No
	// service.AuthUser is ever attached to these calls.
	ClassSecret AuthClass = "secret"

	// ClassAuthenticated admits any authenticated principal regardless of role,
	// including viewer. Enforced by RequireAuthenticated.
	ClassAuthenticated AuthClass = "authenticated"

	// ClassMember admits member and admin, rejecting viewer. Enforced by
	// RequireMember.
	ClassMember AuthClass = "member"

	// ClassAdmin admits admin only. Enforced by RequireAdmin.
	ClassAdmin AuthClass = "admin"

	// ClassCapability admits a caller holding the operation's declared
	// AuthRule.Cap in the namespace the resource hangs from. The namespace is
	// still the authorization anchor (ADR-039: sources and registries inherit
	// their answer from the namespace above them), but the question asked of it
	// is "does your role there grant this capability" rather than "are you the
	// one owner".
	//
	// It replaced an owner class outright rather than sitting beside one
	// (ocidex-y0hg.6). No alias survives, because an alias would let a new
	// operation quietly inherit owner-only semantics without naming what it
	// actually needs.
	//
	// A rule of this class is the only one whose Cap field is meaningful, and it
	// must set one — a capability-class operation with no capability would admit
	// nobody but an admin while reading like a deliberate rule. Enforced by
	// RequireCapability where the target namespace is knowable from the path, or
	// by requireNamespaceCapability inside the handler where it is only knowable
	// from the body. AuthRule.Notes records which.
	ClassCapability AuthClass = "capability"
)

// AuthRule is the declared authorization contract for one operation.
type AuthRule struct {
	// Class is the rule deciding whether the caller may invoke the operation.
	Class AuthClass

	// Cap is the capability a ClassCapability operation requires, and is empty
	// for every other class. It is what the operation declares instead of a
	// role, so that adding a role to authz.roleCaps cannot silently widen an
	// endpoint that never mentioned it.
	Cap authz.Capability

	// Write reports whether the operation also declares RequireWrite, which
	// rejects an API key carrying no mutating capability. True for every
	// state-mutating operation.
	Write bool

	// Notes records anything the class alone does not convey — where the rule
	// is enforced, or what a permitted caller still cannot see.
	Notes string

	// DevOnly reports that the operation is registered only in a development
	// build. Such an operation is absent from a production spec by
	// construction, so the coverage test must not treat its declaration as
	// orphaned and the matrix renders it in its own section rather than
	// dropping it — a rule nobody can see is a rule nobody reviews.
	DevOnly bool
}

// Notes strings repeated across many operations. They carry no behaviour; they
// are constants so a change to the wording lands in one place.
const (
	noteVisFilter        = "VisibilityFilter."
	noteManageRegistryMW = "RequireCapability(manage_source) middleware."
	noteManageMemberMW   = "RequireCapability(manage_member) middleware, on the {id} path param."

	// noteNamespaceScoped marks the operational feeds that any authenticated
	// caller may invoke but which return only rows from the namespaces the
	// caller can see. An admin gets the cross-tenant view from the same
	// endpoint — there is no separate admin path (ocidex-998g.1).
	noteNamespaceScoped = "Rows filtered via visible_namespace_ids; admins see every namespace."

	// noteSelfScoped marks the /users/me/* collections. These select on
	// ownership, not visibility — the distinction that matters for review is
	// that a public resource owned by somebody else is absent here but present
	// in the sibling list endpoint, and that admins get no widening
	// (ocidex-998g.2).
	noteSelfScoped = "Owned rows only; excludes others' public rows, and admins get no widening."

	// noteWatch is deliberately the opposite of noteSelfScoped on the
	// visibility axis, and that asymmetry is the thing to check in review: the
	// watchlist is self-scoped in *whose* it is, but the artifact being watched
	// is chosen from everything the caller can see, which includes other
	// people's public artifacts (ocidex-998g.3).
	noteWatch = "Watch is self-scoped; the artifact must be visible to the caller, which may include others' public artifacts."

	// noteWatchFeed records the one place the watch feature does re-check
	// visibility. The watchlist deliberately does not (see noteWatch), so if a
	// review finds these two agreeing, one of them is wrong.
	noteWatchFeed = "Self-scoped, and additionally visibility-filtered: an artifact made private after being starred stays on the watchlist but stops producing events."
)

// authRules declares the authorization contract of every registered operation,
// keyed by huma operation ID. It is the source of truth for docs/AUTH_MATRIX.md
// and the fixture for the conformance test: adding an operation without adding
// a row here fails TestAuthClassCoverage.
var authRules = map[string]AuthRule{
	// --- Meta ---------------------------------------------------------------
	"health-check": {Class: ClassPublic, Notes: "Liveness probe."},

	// --- Development-only ---------------------------------------------------
	"dev-mint-session": {
		Class:   ClassPublic,
		DevOnly: true,
		Notes:   "POST /api/v1/dev/session. Development builds only; not registered when ENVIRONMENT != development. Mints a real session cookie for a persona seeded by scripts/dev-auth.sh.",
	},
	"readiness-check": {Class: ClassPublic, Notes: "Readiness probe; reports DB reachability."},
	"api-version":     {Class: ClassPublic},

	// --- Auth & users -------------------------------------------------------
	"get-me":             {Class: ClassAuthenticated, Notes: "Returns the calling principal."},
	"list-my-namespaces": {Class: ClassAuthenticated, Notes: noteSelfScoped},
	"list-my-sources":    {Class: ClassAuthenticated, Notes: noteSelfScoped},
	"list-my-clusters":   {Class: ClassAuthenticated, Notes: noteSelfScoped},
	"list-my-registries": {Class: ClassAuthenticated, Notes: noteSelfScoped},
	"list-my-artifacts":  {Class: ClassAuthenticated, Notes: noteSelfScoped},
	"list-my-activity":   {Class: ClassAuthenticated, Notes: noteSelfScoped},
	"list-my-watches":    {Class: ClassAuthenticated, Notes: noteSelfScoped},
	"list-my-watch-feed": {Class: ClassAuthenticated, Notes: noteWatchFeed},
	// The owned variants of two feeds whose siblings are visibility-filtered
	// rather than admin-only; noteSelfScoped applies unchanged, because the
	// narrowing is the same one (ocidex-998g.5).
	"list-my-drift-feed":      {Class: ClassAuthenticated, Notes: noteSelfScoped},
	"list-my-vulnerabilities": {Class: ClassAuthenticated, Notes: noteSelfScoped},
	"watch-artifact":          {Class: ClassAuthenticated, Write: true, Notes: noteWatch},
	"unwatch-artifact":        {Class: ClassAuthenticated, Write: true, Notes: "Removes the caller's own watch; idempotent."},
	"list-auth-providers": {Class: ClassPublic,
		Notes: "Names the operator gave their own issuers; the login page renders these before anyone is signed in."},
	"list-my-identities": {Class: ClassAuthenticated, Notes: "Own identities only; no path segment names a user."},
	"link-identity": {Class: ClassAuthenticated, Write: true,
		Notes: "Links onto the calling account. An identity already held by another account is refused, never merged."},
	"unlink-identity": {Class: ClassAuthenticated, Write: true,
		Notes: "Own identities only; refuses the last one with 409."},
	"create-api-key":   {Class: ClassMember, Write: true, Notes: "Key is scoped to the calling user."},
	"list-api-keys":    {Class: ClassMember, Notes: "Own keys only."},
	"delete-api-key":   {Class: ClassMember, Write: true, Notes: "Own keys only."},
	"list-users":       {Class: ClassAdmin},
	"update-user-role": {Class: ClassAdmin, Write: true},
	"get-system-status": {Class: ClassAdmin,
		Notes: "Exposes DB and job-queue internals."},

	// --- SBOMs --------------------------------------------------------------
	"list-sboms":                   {Class: ClassPublic, Notes: noteVisFilter},
	"lookup-sbom":                  {Class: ClassPublic, Notes: "VisibilityFilter applied before the ambiguity count (ADR-042)."},
	"get-sbom":                     {Class: ClassPublic, Notes: noteVisFilter},
	"get-sbom-dependencies":        {Class: ClassPublic, Notes: noteVisFilter},
	"list-sbom-components":         {Class: ClassPublic, Notes: noteVisFilter},
	"list-sbom-vulns":              {Class: ClassPublic, Notes: noteVisFilter},
	"list-sbom-drift-history":      {Class: ClassPublic, Notes: noteVisFilter},
	"diff-sboms":                   {Class: ClassPublic, Notes: "VisibilityFilter on both sides."},
	"diff-tree":                    {Class: ClassPublic, Notes: "VisibilityFilter on both sides."},
	"ingest-sbom":                  {Class: ClassCapability, Cap: authz.CapIngest, Write: true, Notes: "resolveIngestSource requires the capability in the namespace behind ?source=; RequireMember is the floor beneath it."},
	"delete-sbom":                  {Class: ClassCapability, Cap: authz.CapDeleteArtifact, Write: true, Notes: "RequireCapability(delete_artifact) middleware on the SBOM's namespace."},
	"get-dashboard-stats":          {Class: ClassPublic, Notes: noteVisFilter},
	"get-discovery":                {Class: ClassPublic, Notes: "Public namespaces only, in SQL; no viewer parameter, so the response is identical for every caller."},
	"get-artifact-changelog":       {Class: ClassPublic, Notes: noteVisFilter},
	"get-artifact-license-summary": {Class: ClassPublic, Notes: noteVisFilter},

	// --- Artifacts ----------------------------------------------------------
	"list-artifacts":            {Class: ClassPublic, Notes: noteVisFilter},
	"lookup-artifact":           {Class: ClassPublic, Notes: "VisibilityFilter applied before the ambiguity count (ADR-042)."},
	"get-artifact":              {Class: ClassPublic, Notes: noteVisFilter},
	"list-artifact-sboms":       {Class: ClassPublic, Notes: noteVisFilter},
	"list-artifact-versions":    {Class: ClassPublic, Notes: noteVisFilter},
	"get-artifact-vuln-summary": {Class: ClassPublic, Notes: noteVisFilter},
	"list-artifact-vulns":       {Class: ClassPublic, Notes: noteVisFilter},
	"get-artifact-usages":       {Class: ClassPublic, Notes: "Filtered via visible_namespace_ids (ADR-041)."},
	"get-artifact-contains":     {Class: ClassPublic, Notes: "Filtered via visible_namespace_ids (ADR-041)."},
	"delete-artifact":           {Class: ClassCapability, Cap: authz.CapDeleteArtifact, Write: true, Notes: "RequireCapability(delete_artifact) middleware on the artifact's namespace."},

	// --- Components & licenses ---------------------------------------------
	"search-components":          {Class: ClassPublic, Notes: noteVisFilter},
	"search-distinct-components": {Class: ClassPublic, Notes: noteVisFilter},
	"list-component-purl-types":  {Class: ClassPublic, Notes: noteVisFilter},
	"get-component-versions":     {Class: ClassPublic, Notes: noteVisFilter},
	"get-component":              {Class: ClassPublic, Notes: noteVisFilter},
	"get-component-vulns":        {Class: ClassPublic, Notes: noteVisFilter},
	"list-licenses":              {Class: ClassPublic, Notes: noteVisFilter},
	"lookup-license":             {Class: ClassPublic, Notes: noteVisFilter},
	"list-components-by-license": {Class: ClassPublic, Notes: noteVisFilter},

	// --- Vulnerabilities ----------------------------------------------------
	"list-top-vulnerabilities": {Class: ClassPublic, Notes: noteVisFilter},
	"get-vulnerability":        {Class: ClassPublic, Notes: "Advisory data is not tenant-scoped."},
	// Deliberately not ClassPublic like its two neighbours: the advisory is
	// public data, but "which of these clusters is running it" is inventory,
	// and inventory is gated the same way list-cluster-workloads is.
	"list-vulnerability-workloads": {Class: ClassAuthenticated, Notes: "Workload rows filtered via visible_namespace_ids on the owning namespace, so an invisible cluster contributes nothing rather than 403ing."},

	// --- Namespaces ---------------------------------------------------------
	"list-namespaces":       {Class: ClassAuthenticated, Notes: "Own plus public namespaces."},
	"get-namespace":         {Class: ClassAuthenticated, Notes: "A private namespace the caller does not own 404s, so its existence is not leaked."},
	"get-namespace-by-name": {Class: ClassAuthenticated, Notes: "A private namespace the caller does not own 404s."},
	"create-namespace":      {Class: ClassAuthenticated, Write: true, Notes: "Owned by the calling user."},
	"update-namespace":      {Class: ClassCapability, Cap: authz.CapManageMember, Write: true, Notes: "manage_member capability check in handler."},
	"delete-namespace":      {Class: ClassCapability, Cap: authz.CapDeleteNamespace, Write: true, Notes: "delete_namespace capability check in handler; deletes everything ingested under the namespace."},

	"list-namespace-members":  {Class: ClassCapability, Cap: authz.CapManageMember, Notes: noteManageMemberMW + " Who may see the roster is who may change it."},
	"set-namespace-member":    {Class: ClassCapability, Cap: authz.CapManageMember, Write: true, Notes: noteManageMemberMW + " A caller may not grant a role they do not hold themselves; demoting or removing the owner, or granting a second one, is a 409."},
	"remove-namespace-member": {Class: ClassCapability, Cap: authz.CapManageMember, Write: true, Notes: noteManageMemberMW + " Removing the owner is a 409."},

	// --- Sources ------------------------------------------------------------
	"list-sources":  {Class: ClassAuthenticated, Notes: "Visibility resolved through the owning namespace."},
	"get-source":    {Class: ClassAuthenticated, Notes: "404s when the owning namespace is private and unowned."},
	"create-source": {Class: ClassCapability, Cap: authz.CapManageSource, Write: true, Notes: "manage_source capability on the body's namespace_id."},
	"update-source": {Class: ClassCapability, Cap: authz.CapManageSource, Write: true, Notes: "manage_source capability on the source's namespace."},
	"delete-source": {Class: ClassCapability, Cap: authz.CapManageSource, Write: true, Notes: "manage_source capability on the source's namespace."},

	// --- Clusters -----------------------------------------------------------
	// ADR-044 K8 originally had the inventory push reuse the read-write scope,
	// so a key issued for uploading SBOMs could also push inventory into any
	// cluster its owner had. That is no longer true: a key declares the
	// capabilities it may exercise, and an ingest-only key is refused here even
	// when its owner may push (ADR-046).
	"list-clusters":                 {Class: ClassAuthenticated, Notes: "Visibility resolved through the owning namespace."},
	"get-cluster":                   {Class: ClassAuthenticated, Notes: "404s when the owning namespace is private and unowned."},
	"create-cluster":                {Class: ClassCapability, Cap: authz.CapManageCluster, Write: true, Notes: "manage_cluster capability on the body's namespace_id."},
	"update-cluster":                {Class: ClassCapability, Cap: authz.CapManageCluster, Write: true, Notes: "manage_cluster capability on the cluster's namespace."},
	"delete-cluster":                {Class: ClassCapability, Cap: authz.CapManageCluster, Write: true, Notes: "manage_cluster capability on the cluster's namespace; drops reported inventory only."},
	"put-cluster-inventory":         {Class: ClassCapability, Cap: authz.CapPushInventory, Write: true, Notes: "push_inventory capability on the cluster's namespace — membership, not visibility, because a public namespace must not make inventory writable by anyone."},
	"list-cluster-workloads":        {Class: ClassAuthenticated, Notes: "Cluster gated on namespace visibility; rows additionally filtered via visible_namespace_ids."},
	"list-cluster-images":           {Class: ClassAuthenticated, Notes: "Same gate and same rows as list-cluster-workloads, grouped by image rather than by workload-container."},
	"list-cluster-vulns":            {Class: ClassAuthenticated, Notes: "Same gate as list-cluster-workloads; findings and coverage are returned together so neither can be read without the other."},
	"list-cluster-k8s-namespaces":   {Class: ClassAuthenticated, Notes: "Same gate as list-cluster-workloads; the facet counts describe only the rows that gate admits."},
	"list-cluster-unknown-images":   {Class: ClassAuthenticated, Notes: "Same gate as list-cluster-workloads. It names the namespace's registries, so cluster visibility is what authorizes learning them; resolution never leaves the cluster's own namespace."},
	"ingest-cluster-unknown-images": {Class: ClassCapability, Cap: authz.CapTriggerScan, Write: true, Notes: "trigger_scan, not the visibility that guards the matching list: this spends the namespace's registry credentials and enqueues scan work. It deliberately diverges from put-cluster-inventory, the other trigger for the same action — pushing inventory is what a CI agent does (push_inventory), asking the installation to go scan what it found is not."},

	// --- Registries ---------------------------------------------------------
	"list-registries":            {Class: ClassAuthenticated, Notes: "Own plus public registries."},
	"get-registry":               {Class: ClassAuthenticated, Notes: "A private registry the caller does not own 404s."},
	"get-registry-by-name":       {Class: ClassAuthenticated, Notes: "A private registry the caller does not own 404s."},
	"create-registry":            {Class: ClassAuthenticated, Write: true, Notes: "Creates the namespace and source beneath it, owned by the caller."},
	"update-registry":            {Class: ClassCapability, Cap: authz.CapManageSource, Write: true, Notes: noteManageRegistryMW},
	"delete-registry":            {Class: ClassCapability, Cap: authz.CapManageSource, Write: true, Notes: noteManageRegistryMW},
	"scan-registry":              {Class: ClassCapability, Cap: authz.CapTriggerScan, Write: true, Notes: "RequireCapability(trigger_scan) middleware."},
	"regenerate-webhook-secret":  {Class: ClassCapability, Cap: authz.CapReadSecret, Write: true, Notes: "RequireCapability(read_secret) middleware; response contains the new secret."},
	"test-registry-connection":   {Class: ClassAdmin, Write: true, Notes: "Dials an arbitrary caller-supplied host from inside the cluster."},
	"get-registry-trust-summary": {Class: ClassAuthenticated, Notes: noteNamespaceScoped},
	"list-recent-drift":          {Class: ClassAuthenticated, Notes: noteNamespaceScoped},
	"registry-webhook":           {Class: ClassSecret, Notes: "HMAC over the body against the registry's webhook secret; no user identity."},

	// --- Jobs ---------------------------------------------------------------
	"list-scan-jobs":                   {Class: ClassAuthenticated, Notes: noteNamespaceScoped},
	"get-scan-job":                     {Class: ClassAuthenticated, Notes: "A job outside the caller's visible namespaces 404s."},
	"retry-scan-job":                   {Class: ClassAdmin, Write: true},
	"retry-all-failed-scan-jobs":       {Class: ClassAdmin, Write: true},
	"list-enrichment-jobs":             {Class: ClassAuthenticated, Notes: noteNamespaceScoped},
	"enrichment-jobs-summary":          {Class: ClassAuthenticated, Notes: noteNamespaceScoped},
	"retry-enrichment-job":             {Class: ClassAdmin, Write: true},
	"retry-all-failed-enrichment-jobs": {Class: ClassAdmin, Write: true},
}

// AuthRules returns a copy of the declared authorization contract, keyed by
// operation ID. It exists so the conformance test and cmd/authmatrix can read
// the table from outside the package.
func AuthRules() map[string]AuthRule {
	out := make(map[string]AuthRule, len(authRules))
	for k, v := range authRules {
		out[k] = v
	}
	return out
}

// AuthMatrixRow is one operation's row in the generated authorization matrix.
type AuthMatrixRow struct {
	Tag         string
	Method      string
	Path        string
	OperationID string
	Rule        AuthRule
	// Declared is false when the operation is registered but has no row in
	// authRules. The renderer marks it rather than dropping it, so a stale
	// matrix is visibly stale rather than quietly incomplete.
	Declared bool
}

// AuthMatrixRows joins the registered operations in spec against the
// declarations in authRules, sorted by tag, then path, then method.
func AuthMatrixRows(spec *huma.OpenAPI) []AuthMatrixRow {
	var rows []AuthMatrixRow
	for path, item := range spec.Paths {
		for method, op := range map[string]*huma.Operation{
			"GET": item.Get, "PUT": item.Put, "POST": item.Post,
			"DELETE": item.Delete, "PATCH": item.Patch, "HEAD": item.Head,
			"OPTIONS": item.Options, "TRACE": item.Trace,
		} {
			if op == nil {
				continue
			}
			tag := "Other"
			if len(op.Tags) > 0 {
				tag = op.Tags[0]
			}
			rule, ok := authRules[op.OperationID]
			rows = append(rows, AuthMatrixRow{
				Tag:         tag,
				Method:      method,
				Path:        path,
				OperationID: op.OperationID,
				Rule:        rule,
				Declared:    ok,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Tag != rows[j].Tag {
			return rows[i].Tag < rows[j].Tag
		}
		if rows[i].Path != rows[j].Path {
			return rows[i].Path < rows[j].Path
		}
		return rows[i].Method < rows[j].Method
	})
	return rows
}

// classDescriptions is the legend rendered above the matrix, in escalating
// order of privilege.
var classDescriptions = []struct {
	Class AuthClass
	Desc  string
}{
	{ClassPublic, "No credentials required. Rows the caller may not see are removed by a `VisibilityFilter` in SQL, so an anonymous caller gets a narrower answer rather than a 403."},
	{ClassSecret, "Authenticated by a per-resource shared secret in the request, not by a user identity."},
	{ClassAuthenticated, "Any authenticated principal, `viewer` included. `RequireAuthenticated`."},
	{ClassMember, "`member` or `admin`; `viewer` is rejected with 403. `RequireMember`."},
	{ClassAdmin, "`admin` only; everyone else gets 403. `RequireAdmin`."},
	{ClassCapability, "A caller whose role in the namespace the resource hangs from grants the capability in the **Capability** column, or an `admin`. Per ADR-039 the namespace is the *only* authorization anchor — sources and registries inherit their answer from the namespace above them. Enforced by `RequireCapability` or, where the namespace is only knowable from the request, in the handler; the Notes column says which. The capability each role grants is in the table below."},
}

// AuthMatrixMarkdown renders docs/AUTH_MATRIX.md from the operations registered
// on spec joined against the declarations in authRules.
func AuthMatrixMarkdown(spec *huma.OpenAPI) string {
	var b strings.Builder

	b.WriteString("# Authorization Matrix\n\n")
	b.WriteString("<!-- Generated by `make auth-matrix` from internal/api/authclass.go. Do not edit by hand. -->\n\n")
	b.WriteString("Every registered API operation and the single rule that decides whether a caller may\n")
	b.WriteString("invoke it. The table is generated by joining the live huma spec against the `authRules`\n")
	b.WriteString("declarations in [`internal/api/authclass.go`](../internal/api/authclass.go), so it cannot\n")
	b.WriteString("drift from the router: `make check` fails if this file is stale, and the conformance test\n")
	b.WriteString("in `internal/api/authclass_test.go` fails if an operation is registered without a\n")
	b.WriteString("declaration or a declaration outlives its operation.\n\n")

	b.WriteString("## Auth classes\n\n")
	b.WriteString("| Class | Meaning |\n|---|---|\n")
	for _, cd := range classDescriptions {
		fmt.Fprintf(&b, "| `%s` | %s |\n", cd.Class, cd.Desc)
	}

	writeRoleCapabilityTable(&b)

	b.WriteString("\n## Write scope\n\n")
	b.WriteString("The **Write** column is orthogonal to the class. A ✓ means the operation also declares\n")
	b.WriteString("`RequireWrite`, which rejects (403) an API key whose declared capabilities are all\n")
	b.WriteString("read-only, even when the key's owner passes the class check. It is a coarse gate: the\n")
	b.WriteString("**Capability** column is what narrows an individual operation, and a key is refused\n")
	b.WriteString("there unless it declares that capability *and* its owner's role grants it. Session\n")
	b.WriteString("cookies carry no ceiling and are unaffected.\n\n")

	b.WriteString("## Operations\n\n")

	rows := AuthMatrixRows(spec)
	tag := ""
	for i, r := range rows {
		if r.Tag != tag {
			if i > 0 {
				b.WriteString("\n")
			}
			tag = r.Tag
			fmt.Fprintf(&b, "### %s\n\n", tag)
			b.WriteString("| Method | Path | Operation | Class | Capability | Write | Notes |\n|---|---|---|---|---|---|---|\n")
		}
		class := "**UNDECLARED**"
		if r.Declared {
			class = "`" + string(r.Rule.Class) + "`"
		}
		write := ""
		if r.Rule.Write {
			write = "✓"
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s | %s | %s | %s |\n",
			r.Method, r.Path, r.OperationID, class, capCell(r.Rule), write, r.Rule.Notes)
	}

	writeDevOnlySection(&b, rows)
	return b.String()
}

// writeDevOnlySection lists the declarations marked DevOnly that this spec does
// not contain. Their absence from the table above is the point — the matrix is
// generated from a production router — but an undocumented rule is one nobody
// reviews, so the declarations are rendered here with their absence stated.
func writeDevOnlySection(b *strings.Builder, rows []AuthMatrixRow) {
	registered := make(map[string]bool, len(rows))
	for _, r := range rows {
		registered[r.OperationID] = true
	}
	var ids []string
	for id, rule := range authRules {
		if rule.DevOnly && !registered[id] {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}
	sort.Strings(ids)

	b.WriteString("\n## Development-only operations\n\n")
	b.WriteString("Declared in `authRules` but **not registered above**, because the matrix is generated\n")
	b.WriteString("from a router built without a development config. These operations do not exist in a\n")
	b.WriteString("production build — they are absent from the route table and from `web/openapi.json`,\n")
	b.WriteString("not merely refused at runtime.\n\n")
	b.WriteString("| Operation | Class | Capability | Write | Notes |\n|---|---|---|---|---|\n")
	for _, id := range ids {
		rule := authRules[id]
		write := ""
		if rule.Write {
			write = "✓"
		}
		fmt.Fprintf(b, "| `%s` | `%s` | %s | %s | %s |\n", id, rule.Class, capCell(rule), write, rule.Notes)
	}
}

// capCell renders the Capability column. Only a capability-class rule has one;
// an em dash rather than an empty cell says the other classes answer without
// consulting a namespace role at all, which is the distinction a reader of the
// table is trying to make.
func capCell(rule AuthRule) string {
	if rule.Cap == "" {
		return "—"
	}
	return "`" + string(rule.Cap) + "`"
}

// writeRoleCapabilityTable renders authz's role × capability table into the
// legend. The capability column above names what an operation needs; without
// this table a reader has to open internal/authz/capability.go to learn which
// role grants it, and the answer would be one more thing free to drift out of
// the document (ocidex-y0hg.6).
func writeRoleCapabilityTable(b *strings.Builder) {
	roles := authz.AllRoles()

	b.WriteString("\n## Namespace roles and capabilities\n\n")
	b.WriteString("A `capability` operation asks whether the caller's role **in the namespace the resource\n")
	b.WriteString("hangs from** grants the capability it declares. An installation-wide `admin`\n")
	b.WriteString("short-circuits every cell; an installation-wide `viewer` is capped at `read_private`\n")
	b.WriteString("whatever role a namespace gave them; a non-member holds nothing (ADR-046).\n\n")
	b.WriteString("Generated from `roleCaps` in [`internal/authz/capability.go`](../internal/authz/capability.go).\n\n")

	b.WriteString("| Capability |")
	for _, r := range roles {
		fmt.Fprintf(b, " `%s` |", r)
	}
	b.WriteString("\n|---|")
	for range roles {
		b.WriteString("---|")
	}
	b.WriteString("\n")

	for _, c := range authz.AllCapabilities() {
		fmt.Fprintf(b, "| `%s` |", c)
		for _, r := range roles {
			cell := ""
			if r.Allows(c) {
				cell = "✓"
			}
			fmt.Fprintf(b, " %s |", cell)
		}
		b.WriteString("\n")
	}
}
