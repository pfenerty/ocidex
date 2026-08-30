package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/vuln"
)

// The discovery surface (ocidex-q1z7) is the first endpoint deliberately built
// for unauthenticated viewers, and docs/AUTH_MATRIX.md records why that needs a
// test of its own: read endpoints have no handler gate to fall back on, so if
// the visible_namespace_ids filter is wrong in any one of the four ranking
// queries, private content ships to anonymous callers with nothing to stop it.
//
// The fixtures below are shaped so that every section fails loudly rather than
// subtly if its filter is dropped:
//
//   - discover-shared exists in BOTH namespaces, so the public row's
//     versionCount/sbomCount are 1 only while the filter holds, and the recent
//     row resolves to the older public SBOM rather than the newer private one.
//   - CVE-2030-0001 affects a public purl and a private purl, so its blast
//     radius is 1 only while the filter holds.
//   - MIT licenses one public and two private components, so its spread count
//     is 1 only while the filter holds.
//   - discover-private / CVE-2030-0002 / GPL-3.0-only exist in private content
//     alone, so they must be absent from the payload entirely.
//
// That last group is checked against the raw response body as well as the
// decoded one: a leak into a field this test does not model still shows up as a
// substring.

const (
	discoverPublicPurl  = "pkg:generic/discover-public-lib@1.0"
	discoverPrivatePurl = "pkg:generic/discover-private-lib@9.9"
	discoverSecretPurl  = "pkg:generic/discover-secret-lib@7.7"
)

// discoverSharedPublicSBOM is the public half of the shared artifact. Ingested
// first, so it is also the OLDER of the two — see the recency assertion.
const discoverSharedPublicSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:55555555-5555-5555-5555-555555555555",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/discover-shared@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			"version": "1.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-05-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "discover-public-lib",
			"version": "1.0",
			"purl": "pkg:generic/discover-public-lib@1.0",
			"licenses": [{"license": {"id": "MIT"}}]
		}
	]
}`

// discoverSharedPrivateSBOM is the private half of the SAME artifact: a second
// version, in a private namespace, ingested later.
const discoverSharedPrivateSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:66666666-6666-6666-6666-666666666666",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/discover-shared@sha256:2222222222222222222222222222222222222222222222222222222222222222",
			"version": "2.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-06-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "discover-private-lib",
			"version": "9.9",
			"purl": "pkg:generic/discover-private-lib@9.9",
			"licenses": [{"license": {"id": "MIT"}}]
		}
	]
}`

// discoverPrivateOnlySBOM is an artifact that exists in private content alone.
const discoverPrivateOnlySBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:77777777-7777-7777-7777-777777777777",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/discover-private@sha256:3333333333333333333333333333333333333333333333333333333333333333",
			"version": "5.0",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-07-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "discover-secret-lib",
			"version": "7.7",
			"purl": "pkg:generic/discover-secret-lib@7.7",
			"licenses": [{"license": {"id": "MIT"}}, {"license": {"id": "GPL-3.0-only"}}]
		}
	]
}`

// discoverPayload models the fields this test asserts on. The endpoint body is
// snake_case; the section rows are service DTOs and stay camelCase.
type discoverPayload struct {
	TopArtifacts []struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		UsageCount   int64  `json:"usageCount"`
		VersionCount int64  `json:"versionCount"`
		SbomCount    int64  `json:"sbomCount"`
	} `json:"top_artifacts"`
	RecentArtifacts []struct {
		ArtifactID     string `json:"artifactId"`
		Name           string `json:"name"`
		SbomID         string `json:"sbomId"`
		SubjectVersion string `json:"subjectVersion"`
	} `json:"recent_artifacts"`
	TopVulnerabilities []struct {
		CanonicalID           string `json:"canonicalId"`
		AffectedArtifactCount int64  `json:"affectedArtifactCount"`
		AffectedSbomCount     int64  `json:"affectedSbomCount"`
	} `json:"top_vulnerabilities"`
	LicenseSpread []struct {
		Name           string `json:"name"`
		SpdxID         string `json:"spdxId"`
		ComponentCount int64  `json:"componentCount"`
	} `json:"license_spread"`
	Warming bool `json:"warming"`
}

// fetchDiscovery returns the decoded payload and the raw body it came from.
func fetchDiscovery(t *testing.T, baseURL, apiKey string) (discoverPayload, string) {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/discover", "", apiKey)
	if err != nil {
		t.Fatalf("get discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get discovery: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read discovery body: %v", err)
	}
	var payload discoverPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return payload, string(raw)
}

// ingestInto uploads an SBOM through the public ingest path for a source.
func ingestInto(t *testing.T, baseURL, sourceID, body, apiKey string) {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodPost, baseURL+"/api/v1/sboms?source="+sourceID, body, apiKey)
	if err != nil {
		t.Fatalf("ingest sbom: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("ingest sbom: status %d: %s", resp.StatusCode, msg)
	}
}

func discoverNS(t *testing.T, pool *pgxpool.Pool, prefix string, owner pgtype.UUID, visibility string) string {
	t.Helper()
	name := prefix + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	return seedSource(t, pool, seedNamespace(t, pool, name, owner, visibility), "upload", "ci")
}

func TestDiscoverExcludesPrivateNamespaces(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc, searchSvc := setupServerWithStats(t, pool)
	defer srv.Close()

	is := is.New(t)

	publicOwner := seedUser(t, pool, 7301, "discover-public-owner", "member")
	publicKey, err := authSvc.CreateAPIKey(t.Context(), publicOwner, "public", nil)
	is.NoErr(err)
	privateOwner := seedUser(t, pool, 7302, "discover-private-owner", "member")
	privateKey, err := authSvc.CreateAPIKey(t.Context(), privateOwner, "private", nil)
	is.NoErr(err)
	// Owns nothing in this fixture: the authenticated-non-owner caller.
	outsider := seedUser(t, pool, 7303, "discover-outsider", "member")
	outsiderKey, err := authSvc.CreateAPIKey(t.Context(), outsider, "outsider", nil)
	is.NoErr(err)

	publicSrc := discoverNS(t, pool, "discover-pub", publicOwner, "public")
	privateSrc := discoverNS(t, pool, "discover-priv", privateOwner, "private")

	// Order matters: the private half of the shared artifact is ingested last,
	// so it is the newest SBOM for that artifact.
	ingestInto(t, srv.URL, publicSrc, discoverSharedPublicSBOM, publicKey)
	ingestInto(t, srv.URL, privateSrc, discoverSharedPrivateSBOM, privateKey)
	ingestInto(t, srv.URL, privateSrc, discoverPrivateOnlySBOM, privateKey)

	store := vuln.NewPGStore(pool)
	// One vulnerability spanning both sides of the boundary: the count is the
	// leak vector here, not the name.
	seedVuln(t, store, "CVE-2030-0001", "CRITICAL", discoverPublicPurl)
	seedVuln(t, store, "CVE-2030-0001", "CRITICAL", discoverPrivatePurl)
	// Private content only — must not surface at all.
	seedVuln(t, store, "CVE-2030-0002", "CRITICAL", discoverSecretPurl)

	refreshRollups(t, pool)

	// Before the warmer runs the endpoint reports warming rather than an empty
	// catalog, which also proves the payload below came from the cache the
	// server actually reads.
	cold, _ := fetchDiscovery(t, srv.URL, "")
	is.True(cold.Warming)
	is.Equal(len(cold.TopArtifacts), 0)

	_, err = searchSvc.WarmDiscovery(t.Context())
	is.NoErr(err)

	anonPayload, anonRaw := fetchDiscovery(t, srv.URL, "")
	is.True(!anonPayload.Warming)

	// --- the payload is identical for every caller -------------------------
	//
	// The queries take no viewer parameter, so this is structural rather than
	// incidental. Asserting it here means a future viewer-aware variant cannot
	// be added without this test noticing.
	_, outsiderRaw := fetchDiscovery(t, srv.URL, outsiderKey)
	is.Equal(outsiderRaw, anonRaw)
	// Even the owner of the private namespace reads the public-only payload.
	_, ownerRaw := fetchDiscovery(t, srv.URL, privateKey)
	is.Equal(ownerRaw, anonRaw)

	// --- nothing private appears anywhere in the body ----------------------
	for _, needle := range []string{
		"discover-private",    // the private-only artifact and its component
		"discover-secret-lib", // the private-only component
		"CVE-2030-0002",       // the private-only vulnerability
		"GPL-3.0-only",        // the private-only license
		discoverPrivatePurl,   // the private purl behind the shared CVE
		discoverSecretPurl,    // the private-only purl
	} {
		if strings.Contains(anonRaw, needle) {
			t.Fatalf("private value %q leaked into the discovery payload: %s", needle, anonRaw)
		}
	}

	// --- top artifacts: one artifact, counted from public SBOMs only -------
	is.Equal(len(anonPayload.TopArtifacts), 1)
	top := anonPayload.TopArtifacts[0]
	is.Equal(top.Name, "docker.io/discover-shared")
	// 2 versions and 2 SBOMs exist for this artifact; one of each is private.
	is.Equal(top.VersionCount, int64(1))
	is.Equal(top.SbomCount, int64(1))
	is.Equal(top.UsageCount, int64(0))

	// --- recency: the newest PUBLIC SBOM, not the newest SBOM --------------
	is.Equal(len(anonPayload.RecentArtifacts), 1)
	recent := anonPayload.RecentArtifacts[0]
	is.Equal(recent.Name, "docker.io/discover-shared")
	is.Equal(recent.ArtifactID, top.ID)
	is.Equal(recent.SubjectVersion, "1.0")

	// --- blast radius: public reach only -----------------------------------
	is.Equal(len(anonPayload.TopVulnerabilities), 1)
	v := anonPayload.TopVulnerabilities[0]
	is.Equal(v.CanonicalID, "CVE-2030-0001")
	is.Equal(v.AffectedArtifactCount, int64(1))
	is.Equal(v.AffectedSbomCount, int64(1))

	// --- license spread: public components only ----------------------------
	is.Equal(len(anonPayload.LicenseSpread), 1)
	lic := anonPayload.LicenseSpread[0]
	is.Equal(lic.SpdxID, "MIT")
	// MIT covers three distinct components across the fixture; two are private.
	is.Equal(lic.ComponentCount, int64(1))
}

// TestDiscoverEmptyWhenAllContentIsPrivate is the degenerate case of the same
// rule, and it catches a filter failure the test above cannot: if a query
// returned rows for private content only, the assertions above would still see
// the public artifact and could pass on the other sections' counts.
func TestDiscoverEmptyWhenAllContentIsPrivate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc, searchSvc := setupServerWithStats(t, pool)
	defer srv.Close()

	is := is.New(t)

	owner := seedUser(t, pool, 7311, "discover-only-private", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), owner, "private-only", nil)
	is.NoErr(err)

	privateSrc := discoverNS(t, pool, "discover-allpriv", owner, "private")
	ingestInto(t, srv.URL, privateSrc, discoverPrivateOnlySBOM, ownerKey)

	seedVuln(t, vuln.NewPGStore(pool), "CVE-2030-0002", "CRITICAL", discoverSecretPurl)
	refreshRollups(t, pool)

	_, err = searchSvc.WarmDiscovery(t.Context())
	is.NoErr(err)

	// A warm snapshot of an all-private catalog is empty, and says so — it is
	// not still warming, which is the state the landing page renders as a
	// placeholder.
	payload, raw := fetchDiscovery(t, srv.URL, ownerKey)
	is.True(!payload.Warming)
	is.Equal(len(payload.TopArtifacts), 0)
	is.Equal(len(payload.RecentArtifacts), 0)
	is.Equal(len(payload.TopVulnerabilities), 0)
	is.Equal(len(payload.LicenseSpread), 0)
	if strings.Contains(raw, "discover-private") || strings.Contains(raw, "CVE-2030-0002") {
		t.Fatalf("private content leaked into an all-private discovery payload: %s", raw)
	}
}
