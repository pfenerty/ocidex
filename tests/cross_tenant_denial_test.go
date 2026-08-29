package tests

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
)

// Cross-tenant denial is a 404, never a 403.
//
// internal/api/authclass.go states the property in several Notes — "A private
// namespace the caller does not own 404s, so its existence is not leaked" —
// and until now nothing asserted it end to end. The distinction is the whole
// control: a 403 confirms the resource exists, which is exactly the leak the
// Notes claim is closed. Asserting merely "not 200" would pass on a 403 and
// prove nothing.
//
// The other tenant here is a *real* tenant with a namespace and rows of its
// own, not an anonymous nobody. Against an outsider who owns nothing, a 404
// and a correctly-filtered empty answer are indistinguishable, so the test
// would still pass with the filter removed.

// twinSBOM is a second build of minimalSBOM's subject: the same artifact name
// and the same version, on a different image digest. The digest is what keeps
// it a distinct sbom row under ADR-040's UNIQUE constraint; the shared
// name/version pair is what makes an ADR-042 lookup see two candidates. One
// lands in each tenant, which is the only way to reach the branch where the
// resolver must filter before it counts.
const twinSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:99999999-9999-9999-9999-999999999999",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "docker.io/ubuntu@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"version": "24.04",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-06-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "adduser",
			"version": "3.137ubuntu1",
			"purl": "pkg:deb/ubuntu/adduser@3.137ubuntu1?arch=all&distro=ubuntu-24.04"
		}
	]
}`

// privateRegistryBody mirrors registryBody but private, so the registry inherits
// the tenancy boundary rather than being visible to everyone.
func privateRegistryBody(name string) string {
	return `{"name":"` + name + `","type":"generic","url":"registry.example.com","insecure":false,` +
		`"visibility":"private","scan_mode":"webhook","repositories":[],"repository_patterns":[],"tag_patterns":[]}`
}

// postJSON POSTs and returns the created resource's id, failing with the
// server's body so a rejected fixture is attributable.
func postJSON(t *testing.T, baseURL, path, body, key string) string {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodPost, baseURL+path, body, key)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var buf [4096]byte
		n, _ := resp.Body.Read(buf[:])
		t.Fatalf("POST %s: status %d: %s", path, resp.StatusCode, buf[:n])
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("POST %s: decode: %v", path, err)
	}
	return out.ID
}

// artifactIDForSBOM returns the artifact an ingested SBOM hangs from.
func artifactIDForSBOM(t *testing.T, pool *pgxpool.Pool, sbomID string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(t.Context(),
		`SELECT artifact_id::text FROM sbom WHERE id = $1`, sbomID).Scan(&id); err != nil {
		t.Fatalf("artifact for sbom %s: %v", sbomID, err)
	}
	return id
}

func TestCrossTenantDenialIsNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	ctx := t.Context()

	ownerID := seedUser(t, pool, 7601, "devowner", "member")
	ownerKey, err := authSvc.CreateAPIKey(ctx, ownerID, "devowner", "read-write")
	is.NoErr(err)
	outsiderID := seedUser(t, pool, 7602, "devoutsider", "member")
	outsiderKey, err := authSvc.CreateAPIKey(ctx, outsiderID, "devoutsider", "read-write")
	is.NoErr(err)

	// devowner's tenant. Its artifact is docker.io/alpine, which the outsider
	// has no rows under at all — `artifact` is keyed by name and shared across
	// namespaces, so an artifact both tenants have ingested is legitimately
	// 200 to both and its sub-resources are row-filtered instead. Only an
	// artifact the outsider genuinely has nothing under can demonstrate the
	// existence-non-leak.
	ownerNS := seedNamespace(t, pool, "owner-tenant", ownerID, "private")
	ownerSrc := seedSource(t, pool, ownerNS, "upload", "ci")
	ownerSBOM := mustIngest(t, srv.URL, "/api/v1/sboms?source="+ownerSrc, alpineSBOM, ownerKey)
	ownerArtifact := artifactIDForSBOM(t, pool, ownerSBOM)
	ownerReg := postJSON(t, srv.URL, "/api/v1/registries", privateRegistryBody("owner-reg"), ownerKey)
	ownerCluster := postJSON(t, srv.URL, "/api/v1/clusters",
		`{"namespace_id":"`+ownerNS+`","name":"owner-cluster"}`, ownerKey)

	// devoutsider's own tenant. Without it the outsider owns nothing, and every
	// 404 below would also be produced by a server that simply had no data.
	outsiderNS := seedNamespace(t, pool, "outsider-tenant", outsiderID, "private")
	outsiderSrc := seedSource(t, pool, outsiderNS, "upload", "ci")
	outsiderSBOM := mustIngest(t, srv.URL, "/api/v1/sboms?source="+outsiderSrc, minimalSBOM, outsiderKey)

	// The ADR-042 collision: docker.io/ubuntu at 24.04 now exists in both
	// tenants, on two different image digests.
	ownerTwin := mustIngest(t, srv.URL, "/api/v1/sboms?source="+ownerSrc, twinSBOM, ownerKey)

	refreshRollups(t, pool)

	// Every route that names one of devowner's resources by id. 200 for the
	// owner and 404 — not 403 — for the outsider, in the same run, so a route
	// that is simply broken cannot masquerade as a route that is denying.
	routes := []struct {
		name string
		path string
	}{
		{"namespace by id", "/api/v1/namespaces/" + ownerNS},
		{"namespace by name", "/api/v1/namespaces/by-name/owner-tenant"},
		{"source by id", "/api/v1/sources/" + ownerSrc},
		{"registry by id", "/api/v1/registries/" + ownerReg},
		{"registry by name", "/api/v1/registries/by-name/owner-reg"},
		{"cluster by id", "/api/v1/clusters/" + ownerCluster},
		{"cluster workloads", "/api/v1/clusters/" + ownerCluster + "/workloads"},
		{"cluster images", "/api/v1/clusters/" + ownerCluster + "/images"},
		{"sbom by id", "/api/v1/sboms/" + ownerSBOM},
		{"sbom components", "/api/v1/sboms/" + ownerSBOM + "/components"},
		{"artifact by id", "/api/v1/artifacts/" + ownerArtifact},
	}

	for _, r := range routes {
		t.Run(r.name, func(t *testing.T) {
			if got := statusFor(t, srv.URL+r.path, ownerKey); got != http.StatusOK {
				t.Errorf("GET %s as owner: got %d, want 200", r.path, got)
			}
			got := statusFor(t, srv.URL+r.path, outsiderKey)
			switch got {
			case http.StatusNotFound:
			case http.StatusForbidden:
				t.Errorf("GET %s as outsider: got 403, want 404 — a 403 confirms the resource exists", r.path)
			default:
				t.Errorf("GET %s as outsider: got %d, want 404", r.path, got)
			}
		})
	}

	// The artifact sub-collections answer differently, and correctly. They do
	// not 404 on an invisible artifact — but they do not 404 on a *nonexistent*
	// one either. Both come back 200 with an empty page, so the two cases are
	// indistinguishable and nothing about existence is leaked. Asserting 404
	// here would be asserting the wrong contract; asserting only "200" would
	// pass even if the rows leaked. So assert both halves: the owner sees rows,
	// and the outsider sees exactly what a caller naming a random UUID sees.
	t.Run("artifact sub-collections are empty, not forbidden", func(t *testing.T) {
		const nonexistent = "00000000-0000-0000-0000-0000000000ff"
		for _, sub := range []string{"/versions", "/sboms"} {
			ownerRows := collectionLen(t, srv.URL+"/api/v1/artifacts/"+ownerArtifact+sub, ownerKey)
			if ownerRows == 0 {
				t.Errorf("GET artifact%s as owner: 0 rows, want the owner's own", sub)
			}
			outsiderRows := collectionLen(t, srv.URL+"/api/v1/artifacts/"+ownerArtifact+sub, outsiderKey)
			if outsiderRows != 0 {
				t.Errorf("GET artifact%s as outsider: %d rows, want 0", sub, outsiderRows)
			}
			if got := statusFor(t, srv.URL+"/api/v1/artifacts/"+nonexistent+sub, outsiderKey); got != http.StatusOK {
				t.Errorf("GET nonexistent artifact%s: got %d, want the same 200 an invisible one returns", sub, got)
			}
		}
	})

	// ADR-042: the resolver applies the visibility filter *before* counting
	// candidates. Two SBOMs now share an artifact name and version across the
	// two tenants; each caller must get its own with 200, never a 409 that
	// betrays the existence of the other.
	t.Run("lookup filters before counting", func(t *testing.T) {
		q := url.Values{"artifact": {"docker.io/ubuntu"}, "version": {"24.04"}}.Encode()
		path := "/api/v1/sboms/lookup?" + q

		ownerGot := lookupID(t, srv.URL+path, ownerKey, http.StatusOK)
		if ownerGot != ownerTwin {
			t.Errorf("lookup as owner: got sbom %s, want %s", ownerGot, ownerTwin)
		}
		outsiderGot := lookupID(t, srv.URL+path, outsiderKey, http.StatusOK)
		if outsiderGot != outsiderSBOM {
			t.Errorf("lookup as outsider: got sbom %s, want %s", outsiderGot, outsiderSBOM)
		}
		// Neither namespace is public, so an anonymous caller sees no
		// candidates at all — 404, not the 409 two invisible candidates would
		// produce if the count ran first.
		if got := statusFor(t, srv.URL+path, ""); got != http.StatusNotFound {
			t.Errorf("lookup as anonymous: got %d, want 404", got)
		}
	})
}

func statusFor(t *testing.T, url, key string) int {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, url, "", key)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func lookupID(t *testing.T, url, key string, wantStatus int) string {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, url, "", key)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s: status %d, want %d", url, resp.StatusCode, wantStatus)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("GET %s: decode: %v", url, err)
	}
	return out.ID
}

// collectionLen reports how many rows a paginated collection returned, failing
// the test on any non-200.
func collectionLen(t *testing.T, url, key string) int {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, url, "", key)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d, want 200", url, resp.StatusCode)
	}
	var body struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("GET %s: decode: %v", url, err)
	}
	return len(body.Data)
}
