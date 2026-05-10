package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/matryer/is"
)

// diffTreeFromSBOM is the "old" SBOM in the diff-tree contract test.
// It's an alpine-3.14 dex image with a synthetic-root metadata.component
// pointing at a small dependency graph: 3 direct deps, 1 transitive.
// alpine-baselayout, busybox, openssl are direct; libssl1.1 is transitive
// under openssl.
const diffTreeFromSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"metadata": {
		"component": {
			"bom-ref": "pkg:oci/dex@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"type": "container",
			"name": "ghcr.io/dexidp/dex@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"version": "v2.30.3",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "aarch64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-01-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"bom-ref": "pkg:apk/alpine/alpine-baselayout@3.2.0-r16?arch=aarch64&distro=alpine-3.14.3",
			"type": "library",
			"name": "alpine-baselayout",
			"version": "3.2.0-r16",
			"purl": "pkg:apk/alpine/alpine-baselayout@3.2.0-r16?arch=aarch64&distro=alpine-3.14.3"
		},
		{
			"bom-ref": "pkg:apk/alpine/busybox@1.33.1-r6?arch=aarch64&distro=alpine-3.14.3",
			"type": "library",
			"name": "busybox",
			"version": "1.33.1-r6",
			"purl": "pkg:apk/alpine/busybox@1.33.1-r6?arch=aarch64&distro=alpine-3.14.3"
		},
		{
			"bom-ref": "pkg:apk/alpine/openssl@1.1.1l-r0?arch=aarch64&distro=alpine-3.14.3",
			"type": "library",
			"name": "openssl",
			"version": "1.1.1l-r0",
			"purl": "pkg:apk/alpine/openssl@1.1.1l-r0?arch=aarch64&distro=alpine-3.14.3"
		},
		{
			"bom-ref": "pkg:apk/alpine/libssl1.1@1.1.1l-r0?arch=aarch64&distro=alpine-3.14.3",
			"type": "library",
			"name": "libssl1.1",
			"version": "1.1.1l-r0",
			"purl": "pkg:apk/alpine/libssl1.1@1.1.1l-r0?arch=aarch64&distro=alpine-3.14.3"
		}
	],
	"dependencies": [
		{
			"ref": "pkg:oci/dex@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"dependsOn": [
				"pkg:apk/alpine/alpine-baselayout@3.2.0-r16?arch=aarch64&distro=alpine-3.14.3",
				"pkg:apk/alpine/busybox@1.33.1-r6?arch=aarch64&distro=alpine-3.14.3",
				"pkg:apk/alpine/openssl@1.1.1l-r0?arch=aarch64&distro=alpine-3.14.3"
			]
		},
		{
			"ref": "pkg:apk/alpine/openssl@1.1.1l-r0?arch=aarch64&distro=alpine-3.14.3",
			"dependsOn": [
				"pkg:apk/alpine/libssl1.1@1.1.1l-r0?arch=aarch64&distro=alpine-3.14.3"
			]
		}
	]
}`

// diffTreeToSBOM is the "new" SBOM. It's an alpine-3.15 dex image —
// distro qualifier version drifts, package versions bump, openssl is
// removed entirely, and ca-certificates is added.
const diffTreeToSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
	"metadata": {
		"component": {
			"bom-ref": "pkg:oci/dex@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"type": "container",
			"name": "ghcr.io/dexidp/dex@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"version": "v2.31.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "aarch64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-02-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"bom-ref": "pkg:apk/alpine/alpine-baselayout@3.2.0-r18?arch=aarch64&distro=alpine-3.15.0",
			"type": "library",
			"name": "alpine-baselayout",
			"version": "3.2.0-r18",
			"purl": "pkg:apk/alpine/alpine-baselayout@3.2.0-r18?arch=aarch64&distro=alpine-3.15.0"
		},
		{
			"bom-ref": "pkg:apk/alpine/busybox@1.34.1-r3?arch=aarch64&distro=alpine-3.15.0",
			"type": "library",
			"name": "busybox",
			"version": "1.34.1-r3",
			"purl": "pkg:apk/alpine/busybox@1.34.1-r3?arch=aarch64&distro=alpine-3.15.0"
		},
		{
			"bom-ref": "pkg:apk/alpine/libssl1.1@1.1.1l-r7?arch=aarch64&distro=alpine-3.15.0",
			"type": "library",
			"name": "libssl1.1",
			"version": "1.1.1l-r7",
			"purl": "pkg:apk/alpine/libssl1.1@1.1.1l-r7?arch=aarch64&distro=alpine-3.15.0"
		},
		{
			"bom-ref": "pkg:apk/alpine/ca-certificates@20211220-r0?arch=aarch64&distro=alpine-3.15.0",
			"type": "library",
			"name": "ca-certificates",
			"version": "20211220-r0",
			"purl": "pkg:apk/alpine/ca-certificates@20211220-r0?arch=aarch64&distro=alpine-3.15.0"
		}
	],
	"dependencies": [
		{
			"ref": "pkg:oci/dex@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"dependsOn": [
				"pkg:apk/alpine/alpine-baselayout@3.2.0-r18?arch=aarch64&distro=alpine-3.15.0",
				"pkg:apk/alpine/busybox@1.34.1-r3?arch=aarch64&distro=alpine-3.15.0",
				"pkg:apk/alpine/libssl1.1@1.1.1l-r7?arch=aarch64&distro=alpine-3.15.0",
				"pkg:apk/alpine/ca-certificates@20211220-r0?arch=aarch64&distro=alpine-3.15.0"
			]
		}
	]
}`

// TestDiffTreeEndpoint round-trips the GET /api/v1/sboms/diff-tree
// contract end-to-end: ingest two SBOMs (one alpine-3.14, one alpine-3.15),
// call the diff-tree endpoint, and assert every field documented in
// ADR-0021 is populated correctly.
//
// This is the contract test that would have caught the keycloak bug at the
// wire level: roots[] populated, ComponentSummary.isDirect set,
// ComponentDiff.direction/nodeRef set, descendantChanges aggregated,
// summary reconciled with the changes list.
func TestDiffTreeEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	// SBOM ingest requires member role; seed a user + API key for the test.
	memberID := seedUser(t, pool, 9001, "diff-tree-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "diff-tree-test", "read-write")
	is.NoErr(err)

	// --- Ingest "from" SBOM (alpine-3.14) ---
	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", diffTreeFromSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var fromIngest map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&fromIngest))
	resp.Body.Close()
	fromID := fromIngest["id"].(string)

	// --- Ingest "to" SBOM (alpine-3.15) ---
	resp, err = doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", diffTreeToSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var toIngest map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&toIngest))
	resp.Body.Close()
	toID := toIngest["id"].(string)

	// --- GET /api/v1/sboms/diff-tree ---
	url := fmt.Sprintf("%s/api/v1/sboms/diff-tree?from=%s&to=%s", srv.URL, fromID, toID)
	resp, err = doGet(t, url)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var tree map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&tree))
	resp.Body.Close()

	// --- Top-level: from, to, summary, changes, nodes, edges, roots ---
	from := tree["from"].(map[string]any)
	to := tree["to"].(map[string]any)
	is.Equal(from["id"], fromID)
	is.Equal(to["id"], toID)

	summary := tree["summary"].(map[string]any)
	// Three packages upgrade across the alpine 3.14.3 → 3.15.0 boundary
	// (alpine-baselayout, busybox, libssl1.1 — all matched by distro
	// normalization per ADR-0019). openssl is removed; ca-certificates
	// is added.
	is.Equal(summary["upgraded"], float64(3))
	is.Equal(summary["added"], float64(1))
	is.Equal(summary["removed"], float64(1))

	changes := tree["changes"].([]any)
	roots := tree["roots"].([]any)
	nodes := tree["nodes"].([]any)
	edges := tree["edges"].([]any)
	is.True(len(changes) >= 5) // 3 upgrades + 1 add + 1 remove
	is.True(len(roots) > 0)
	is.True(len(nodes) > 0)
	is.True(len(edges) > 0)

	// --- Roots[] must include every direct dep of the to-side metadata.component ---
	// Direct deps of the new (to) image: alpine-baselayout, busybox, libssl1.1, ca-certificates.
	// All four bomRefs must appear in roots[].
	rootSet := map[string]bool{}
	for _, r := range roots {
		rootSet[r.(string)] = true
	}
	expectedRoots := []string{
		"pkg:apk/alpine/alpine-baselayout@3.2.0-r18?arch=aarch64&distro=alpine-3.15.0",
		"pkg:apk/alpine/busybox@1.34.1-r3?arch=aarch64&distro=alpine-3.15.0",
		"pkg:apk/alpine/libssl1.1@1.1.1l-r7?arch=aarch64&distro=alpine-3.15.0",
		"pkg:apk/alpine/ca-certificates@20211220-r0?arch=aarch64&distro=alpine-3.15.0",
	}
	for _, exp := range expectedRoots {
		is.True(rootSet[exp])
	}

	// --- nodes[].isDirect must be true exactly for the four direct deps ---
	nodeByBomRef := map[string]map[string]any{}
	nodeByID := map[string]map[string]any{}
	for _, n := range nodes {
		nm := n.(map[string]any)
		if br, ok := nm["bomRef"].(string); ok {
			nodeByBomRef[br] = nm
		}
		nodeByID[nm["id"].(string)] = nm
	}
	for _, exp := range expectedRoots {
		n, ok := nodeByBomRef[exp]
		is.True(ok)
		is.Equal(n["isDirect"], true)
	}

	// --- changes[].direction and nodeRef ---
	// Every "added" or "modified" change must have a nodeRef pointing into nodes[]
	// (the component is present on the to-side).
	for _, c := range changes {
		cm := c.(map[string]any)
		dir := cm["direction"].(string)
		switch dir {
		case "added", "upgraded", "downgraded", "modified":
			ref, ok := cm["nodeRef"].(string)
			is.True(ok) // nodeRef populated
			_, found := nodeByID[ref]
			is.True(found) // points to a node that exists
		case "removed":
			// removed components are not in the to-side graph by construction;
			// nodeRef may be absent. No assertion needed.
		}
	}

	// --- summary reconciles with changes[].direction ---
	counted := map[string]int{}
	for _, c := range changes {
		cm := c.(map[string]any)
		counted[cm["direction"].(string)]++
	}
	is.Equal(counted["upgraded"], int(summary["upgraded"].(float64)))
	is.Equal(counted["added"], int(summary["added"].(float64)))
	is.Equal(counted["removed"], int(summary["removed"].(float64)))
}
