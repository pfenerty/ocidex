package api

import (
	"fmt"
	"sort"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// AuthClass is the authorization class of an operation: the single rule that
// decides whether a caller may invoke it at all. Every registered operation
// declares exactly one, and TestAuthClassCoverage fails the build if one is
// missing, stale, or contradicted by the router's middleware wiring.
//
// The class is orthogonal to API-key scope. Scope is declared separately by
// AuthRule.Write, which corresponds to RequireWrite in the router: a mutating
// operation declares a class *and* Write, never Write alone.
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

	// ClassOwner admits the owner of the namespace the resource hangs from, or
	// an admin (ADR-039: namespace ownership is the only ownership check in the
	// system — sources and registries inherit their answer from the namespace
	// above them). Enforced either by an ownership middleware
	// (Require{Registry,SBOM,Artifact}Owner) or, where the target namespace is
	// only knowable from the request body, by canManageNamespace /
	// namespaceOwnerCheck inside the handler. AuthRule.Notes records which.
	ClassOwner AuthClass = "owner"
)

// AuthRule is the declared authorization contract for one operation.
type AuthRule struct {
	// Class is the rule deciding whether the caller may invoke the operation.
	Class AuthClass

	// Write reports whether the operation also declares RequireWrite, which
	// rejects a read-scoped API key. True for every state-mutating operation.
	Write bool

	// Notes records anything the class alone does not convey — where the rule
	// is enforced, or what a permitted caller still cannot see.
	Notes string
}

// Notes strings repeated across many operations. They carry no behaviour; they
// are constants so a change to the wording lands in one place.
const (
	noteVisFilter       = "VisibilityFilter."
	noteRegistryOwnerMW = "RequireRegistryOwner middleware."
)

// authRules declares the authorization contract of every registered operation,
// keyed by huma operation ID. It is the source of truth for docs/AUTH_MATRIX.md
// and the fixture for the conformance test: adding an operation without adding
// a row here fails TestAuthClassCoverage.
var authRules = map[string]AuthRule{
	// --- Meta ---------------------------------------------------------------
	"health-check":    {Class: ClassPublic, Notes: "Liveness probe."},
	"readiness-check": {Class: ClassPublic, Notes: "Readiness probe; reports DB reachability."},
	"api-version":     {Class: ClassPublic},

	// --- Auth & users -------------------------------------------------------
	"get-me":           {Class: ClassAuthenticated, Notes: "Returns the calling principal."},
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
	"list-sbom-drift-history":      {Class: ClassPublic, Notes: noteVisFilter},
	"diff-sboms":                   {Class: ClassPublic, Notes: "VisibilityFilter on both sides."},
	"diff-tree":                    {Class: ClassPublic, Notes: "VisibilityFilter on both sides."},
	"ingest-sbom":                  {Class: ClassMember, Write: true, Notes: "Caller must also own the namespace behind ?source= (resolveIngestSource)."},
	"delete-sbom":                  {Class: ClassOwner, Write: true, Notes: "RequireSBOMOwner middleware."},
	"get-dashboard-stats":          {Class: ClassPublic, Notes: noteVisFilter},
	"get-artifact-changelog":       {Class: ClassPublic, Notes: noteVisFilter},
	"get-artifact-license-summary": {Class: ClassPublic, Notes: noteVisFilter},

	// --- Artifacts ----------------------------------------------------------
	"list-artifacts":            {Class: ClassPublic, Notes: noteVisFilter},
	"lookup-artifact":           {Class: ClassPublic, Notes: "VisibilityFilter applied before the ambiguity count (ADR-042)."},
	"get-artifact":              {Class: ClassPublic, Notes: noteVisFilter},
	"list-artifact-sboms":       {Class: ClassPublic, Notes: noteVisFilter},
	"list-artifact-versions":    {Class: ClassPublic, Notes: noteVisFilter},
	"get-artifact-vuln-summary": {Class: ClassPublic, Notes: noteVisFilter},
	"get-artifact-usages":       {Class: ClassPublic, Notes: "Filtered via visible_namespace_ids (ADR-041)."},
	"get-artifact-contains":     {Class: ClassPublic, Notes: "Filtered via visible_namespace_ids (ADR-041)."},
	"delete-artifact":           {Class: ClassOwner, Write: true, Notes: "RequireArtifactOwner middleware."},

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

	// --- Namespaces ---------------------------------------------------------
	"list-namespaces":       {Class: ClassAuthenticated, Notes: "Own plus public namespaces."},
	"get-namespace":         {Class: ClassAuthenticated, Notes: "A private namespace the caller does not own 404s, so its existence is not leaked."},
	"get-namespace-by-name": {Class: ClassAuthenticated, Notes: "A private namespace the caller does not own 404s."},
	"create-namespace":      {Class: ClassAuthenticated, Write: true, Notes: "Owned by the calling user."},
	"update-namespace":      {Class: ClassOwner, Write: true, Notes: "canManageNamespace in handler."},
	"delete-namespace":      {Class: ClassOwner, Write: true, Notes: "canManageNamespace in handler; deletes everything ingested under the namespace."},

	// --- Sources ------------------------------------------------------------
	"list-sources":  {Class: ClassAuthenticated, Notes: "Visibility resolved through the owning namespace."},
	"get-source":    {Class: ClassAuthenticated, Notes: "404s when the owning namespace is private and unowned."},
	"create-source": {Class: ClassOwner, Write: true, Notes: "namespaceOwnerCheck on the body's namespace_id."},
	"update-source": {Class: ClassOwner, Write: true, Notes: "namespaceOwnerCheck on the source's namespace."},
	"delete-source": {Class: ClassOwner, Write: true, Notes: "namespaceOwnerCheck on the source's namespace."},

	// --- Registries ---------------------------------------------------------
	"list-registries":            {Class: ClassAuthenticated, Notes: "Own plus public registries."},
	"get-registry":               {Class: ClassAuthenticated, Notes: "A private registry the caller does not own 404s."},
	"get-registry-by-name":       {Class: ClassAuthenticated, Notes: "A private registry the caller does not own 404s."},
	"create-registry":            {Class: ClassAuthenticated, Write: true, Notes: "Creates the namespace and source beneath it, owned by the caller."},
	"update-registry":            {Class: ClassOwner, Write: true, Notes: noteRegistryOwnerMW},
	"delete-registry":            {Class: ClassOwner, Write: true, Notes: noteRegistryOwnerMW},
	"scan-registry":              {Class: ClassOwner, Write: true, Notes: noteRegistryOwnerMW},
	"regenerate-webhook-secret":  {Class: ClassOwner, Write: true, Notes: "RequireRegistryOwner middleware; response contains the new secret."},
	"test-registry-connection":   {Class: ClassAdmin, Write: true, Notes: "Dials an arbitrary caller-supplied host from inside the cluster."},
	"get-registry-trust-summary": {Class: ClassAdmin},
	"list-recent-drift":          {Class: ClassAdmin},
	"registry-webhook":           {Class: ClassSecret, Notes: "HMAC over the body against the registry's webhook secret; no user identity."},

	// --- Jobs ---------------------------------------------------------------
	"list-scan-jobs":                   {Class: ClassAuthenticated},
	"get-scan-job":                     {Class: ClassAuthenticated},
	"retry-scan-job":                   {Class: ClassAdmin, Write: true},
	"retry-all-failed-scan-jobs":       {Class: ClassAdmin, Write: true},
	"list-enrichment-jobs":             {Class: ClassAuthenticated},
	"enrichment-jobs-summary":          {Class: ClassAuthenticated},
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
	{ClassOwner, "The owner of the namespace the resource hangs from, or an `admin`. Per ADR-039 namespace ownership is the *only* ownership check — sources and registries inherit their answer from the namespace above them. Enforced by an ownership middleware or, where the namespace is only knowable from the body, in the handler; the Notes column says which."},
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

	b.WriteString("\n## Write scope\n\n")
	b.WriteString("The **Write** column is orthogonal to the class. A ✓ means the operation also declares\n")
	b.WriteString("`RequireWrite`, which rejects an API key issued with the `read` scope (403) even when the\n")
	b.WriteString("key's owner passes the class check. Session cookies and `read-write` keys are unaffected.\n\n")

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
			b.WriteString("| Method | Path | Operation | Class | Write | Notes |\n|---|---|---|---|---|---|\n")
		}
		class := "**UNDECLARED**"
		if r.Declared {
			class = "`" + string(r.Rule.Class) + "`"
		}
		write := ""
		if r.Rule.Write {
			write = "✓"
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s | %s | %s |\n",
			r.Method, r.Path, r.OperationID, class, write, r.Rule.Notes)
	}
	return b.String()
}
