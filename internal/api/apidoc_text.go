package api

import "github.com/danielgtaylor/huma/v2"

// apiIntro is the opening page of the API reference (/api/docs) and the
// spec's info.description. It is Markdown, and it covers what every operation
// shares, so that the operations themselves need not repeat it.
const apiIntro = `OCIDex catalogs container images and the SBOMs that describe them. It enriches
them with vulnerability, provenance and image metadata, and answers questions across
them: what changed between two versions, which images carry an advisory, and what a
Kubernetes cluster is actually running.

## Authentication

Reads of public namespaces need no credentials. Everything else accepts either of:

- **API key**: send ` + "`Authorization: Bearer ocidex_…`" + `. Create a key on the app's
  API keys page (` + "`/admin/keys`" + `) or with ` + "`POST /api/v1/auth/keys`" + `. A key acts with
  the role its owner holds in each namespace, narrowed to the capabilities it was
  created with.
- **Session cookie**: set when you sign in to the web app. Requests sent from this page
  use it automatically. State-changing requests carrying a cookie must come from the
  app's own origin.

A resource you are not allowed to see answers ` + "`404`" + `, the same as one that does not
exist, so the API never confirms what a private namespace contains.

## Errors

Errors are problem documents (RFC 9457, ` + "`application/problem+json`" + `) carrying ` + "`status`" + `,
` + "`title`" + ` and ` + "`detail`" + `. Validation failures add ` + "`errors[]`" + `, one entry per rejected
field, with its location. A rate-limited request gets ` + "`429`" + ` and a ` + "`Retry-After`" + ` header.

## Pagination

Lists use one of two envelopes, and each operation says which:

- **Offset**, for numbered pages over computed results: send ` + "`limit`" + ` and ` + "`offset`" + `,
  and read ` + "`pagination.total`" + `, ` + "`limit`" + ` and ` + "`offset`" + `.
- **Keyset**, for append-only lists: send ` + "`limit`" + `, then pass ` + "`pagination.nextCursor`" + `
  back as ` + "`cursor`" + ` while ` + "`pagination.hasMore`" + ` is true. Cursors are opaque.

## Versioning

Every stable operation lives under ` + "`/api/v1`" + `, and ` + "`/api/v1`" + ` only changes additively:
new operations, new optional parameters, new response fields. Clients should ignore
fields they do not recognise. ` + "`info.version`" + ` is the version of this contract, not of
the server. The running server's build is reported by ` + "`GET /api/v1/`" + `.

## This document

The specification is served by every OCIDex server at ` + "`/api/openapi.json`" + ` and
` + "`/api/openapi.yaml`" + `, and is attached to each release.
`

// apiTags gives each operation group in the reference its heading text. Every
// tag an operation uses must appear here (TestOpenAPITagsAreDescribed).
var apiTags = []*huma.Tag{
	{Name: tagApprovals, Description: "Agent writes held for a person's approval. A key can require approval for chosen capabilities; its requests then return 202 with a pending action, which a person approves or denies from a signed-in session."},
	{Name: tagArtifacts, Description: "An artifact is a named thing OCIDex has SBOMs for, usually a container image repository. Look artifacts up by name, and read their versions, changelog, licenses, vulnerabilities, and the artifacts they ship or are shipped in."},
	{Name: tagSBOMs, Description: "Upload, look up and read SBOMs, with the image metadata, provenance and signing status derived from them. Diff two SBOMs to see the components and vulnerabilities that changed between them."},
	{Name: tagComponents, Description: "Packages found inside SBOMs, identified by purl, with the versions and artifacts each appears in."},
	{Name: tagLicenses, Description: "Licenses declared by components, and the components that declare each one."},
	{Name: tagVulns, Description: "Advisories matched to components, with severity and the artifacts and SBOMs they affect."},
	{Name: tagClusters, Description: "Kubernetes clusters that report what they run through the OCIDex agent: inventory, coverage, running vulnerabilities, and the gaps where an image has no SBOM."},
	{Name: tagRegistries, Description: "OCI registries OCIDex scans for images, with their credentials, repository patterns and scan schedule, and the webhook a registry calls when an image is pushed."},
	{Name: tagSources, Description: "Where SBOMs come from. A source is an OCI registry, a cluster, or an upload source for CI pipelines that push SBOMs directly."},
	{Name: tagNamespaces, Description: "Namespaces own everything else and decide who can see and change it. Manage namespaces, their visibility and their members' roles."},
	{Name: tagJobs, Description: "Background scan and enrichment jobs: their state and errors. Retrying and cancelling jobs requires the admin role."},
	{Name: tagAuth, Description: "Sign-in, the current user, and API keys."},
	{Name: tagAdmin, Description: "Server-wide status. Requires the admin role."},
	{Name: tagStats, Description: "Summary counts for the dashboard."},
	{Name: tagDiscovery, Description: "The public landing payload: what a signed-out visitor can browse."},
	{Name: tagMeta, Description: "The API's own version and build."},
	{Name: tagHealth, Description: "Liveness and readiness probes for orchestrators. Not authenticated."},
}
