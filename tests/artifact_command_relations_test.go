package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
)

// Command-artifact relationships (ADR-048, ocidex-7gf7.11).
//
// One Go module ships many commands, and Syft's binary cataloger names all of
// them after the module: every ocidex image records the same
// pkg:golang/github.com/pfenerty/ocidex component. ADR-041 R1 therefore matched
// none of the twelve artifacts push-sboms.nu declares as .../cmd/<name>, and a
// rule matching on the module alone would have matched all twelve to every
// image — a wrong answer rather than a missing one.
//
// So the assertion that carries this file is not "git-worker relates to its
// image". It is "and vuln-worker does not", which is the half a plain prefix
// rule gets wrong.

const ocidexModule = "github.com/pfenerty/ocidex"

// digestOf derives a distinct sha256 digest per fixture.
//
// Spelling these out by hand is what broke this file the first time: an image
// named ...@sha256:1111… and a binary uploaded with digest sha256:1111… are one
// SBOM as far as the unique index on sbom.digest is concerned, and ingest
// answers a duplicate with 201 and no new artifact — so the collision showed up
// only as a later "no rows in result set". Hashing the fixture's own identity
// makes a collision impossible rather than merely unlikely.
func digestOf(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// cmdImageSBOM is a distroless image carrying one Go binary. The component is
// the main module — that is all Syft emits — so syft:location:0:path is the
// only thing in the document that says which command the binary is.
func cmdImageSBOM(serial int, command, locationPath string) string {
	location := ""
	if locationPath != "" {
		location = fmt.Sprintf(`,
				{"name": "syft:location:0:path", "value": %q}`, locationPath)
	}
	return fmt.Sprintf(`{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:52000000-0000-0000-0000-%012d",
	"version": 1,
	"metadata": {
		"component": {
			"type": "container",
			"name": "ghcr.io/pfenerty/ocidex-%s@%s",
			"version": "v0.0.2",
			"properties": [
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2026-02-01T00:00:00Z"}
			]
		}
	},
	"components": [
		{
			"type": "library",
			"name": "github.com/pfenerty/ocidex",
			"version": "v0.0.2",
			"purl": "pkg:golang/github.com/pfenerty/ocidex@v0.0.2",
			"properties": [
				{"name": "syft:package:foundBy", "value": "go-module-binary-cataloger"}%s
			]
		}
	]
}`, serial, command, digestOf(fmt.Sprintf("image-%d-%s", serial, command)), location)
}

// cmdBinarySBOM is one uploaded command binary, of the shape
// .tektonic/jobs/sbom-push/push-sboms.nu uploads.
func cmdBinarySBOM(serial int, command string) string {
	return fmt.Sprintf(`{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:52000000-0000-0000-0000-1%011d",
	"version": 1,
	"metadata": {
		"component": {
			"type": "application",
			"name": %q,
			"version": "v0.0.2"
		}
	},
	"components": [
		{"type": "library", "name": "chi", "version": "5.0.12", "purl": "pkg:golang/github.com/go-chi/chi/v5@5.0.12"}
	]
}`, serial, command)
}

// cmdUploadPath declares a command artifact's identity at upload (ADR-040),
// mirroring push-sboms.nu: the name is the binary's filename, group and purl
// carry the module, and the purl takes no @version.
func cmdUploadPath(sourceID, name, module, digest string) string {
	q := url.Values{
		"source":        {sourceID},
		"subject_type":  {"application"},
		"subject_name":  {name},
		"subject_group": {module},
		"subject_purl":  {"pkg:golang/" + module + "/cmd/" + name},
		"digest":        {digest},
	}
	return "/api/v1/sboms?" + q.Encode()
}

// artifactIDByNameGroup disambiguates two artifacts sharing a name, which is
// the whole point of the look-alike fixture below.
func artifactIDByNameGroup(t *testing.T, pool *pgxpool.Pool, name, group string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(t.Context(),
		`SELECT id::text FROM artifact WHERE name = $1 AND group_name = $2`, name, group).Scan(&id)
	if err != nil {
		t.Fatalf("artifact %q/%q: %v", group, name, err)
	}
	return id
}

// relationNames returns the counterpart artifact names of one direction, which
// is what every assertion here is actually about.
func relationNames(entries []relationEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.ArtifactName)
	}
	return out
}

// TestCommandArtifactsMatchTheirImageByBinaryPath is ADR-048 R6: an image
// resolves to the one command it actually ships, not to every command built
// from the same module.
func TestCommandArtifactsMatchTheirImageByBinaryPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7601, "cmd-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", nil)
	is.NoErr(err)

	nsID := seedNamespace(t, pool, "cmd-ns", ownerID, "public")
	registrySrc := seedSource(t, pool, nsID, "oci_registry", "ghcr")
	uploadSrc := seedSource(t, pool, nsID, "upload", "ci")

	// One image per command. Both record the identical module component; only
	// the binary the scanner read differs.
	ingestOK(t, srv.URL, ownerKey, "/api/v1/sboms?source="+registrySrc,
		cmdImageSBOM(1, "git-worker", "/git-worker"))
	ingestOK(t, srv.URL, ownerKey, "/api/v1/sboms?source="+registrySrc,
		cmdImageSBOM(2, "vuln-worker", "/vuln-worker"))

	// Two of the module's commands, tracked as artifacts in their own right.
	ingestOK(t, srv.URL, ownerKey,
		cmdUploadPath(uploadSrc, "git-worker", ocidexModule, digestOf("binary-git-worker")),
		cmdBinarySBOM(1, "git-worker"))
	ingestOK(t, srv.URL, ownerKey,
		cmdUploadPath(uploadSrc, "vuln-worker", ocidexModule, digestOf("binary-vuln-worker")),
		cmdBinarySBOM(2, "vuln-worker"))

	gitImageID := artifactIDByName(t, pool, "ghcr.io/pfenerty/ocidex-git-worker")
	gitBinID := artifactIDByName(t, pool, "git-worker")
	vulnBinID := artifactIDByName(t, pool, "vuln-worker")

	// The image resolves to exactly the command its binary is. Without the
	// basename check this list would hold both commands.
	contains := fetchRelations(t, srv.URL, ownerKey, gitImageID, "contains")
	is.Equal(relationNames(contains), []string{"git-worker"})
	is.Equal(contains[0].ArtifactID, gitBinID)

	// The inverse direction agrees, and reaches across the two sources.
	usages := fetchRelations(t, srv.URL, ownerKey, gitBinID, "usages")
	is.Equal(relationNames(usages), []string{"ghcr.io/pfenerty/ocidex-git-worker"})

	// The other command sees only its own image, though both were built from
	// the same module and carry the same component purl.
	vulnUsages := fetchRelations(t, srv.URL, ownerKey, vulnBinID, "usages")
	is.Equal(relationNames(vulnUsages), []string{"ghcr.io/pfenerty/ocidex-vuln-worker"})
}

// TestCommandMatchRequiresARecordedBinaryPath is ADR-048 R7 plus the path
// boundary: the rule fails closed on an unknown path, and a module purl never
// reaches a longer module that merely starts with the same characters.
func TestCommandMatchRequiresARecordedBinaryPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	ownerID := seedUser(t, pool, 7602, "nopath-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", nil)
	is.NoErr(err)

	nsID := seedNamespace(t, pool, "nopath-ns", ownerID, "public")
	registrySrc := seedSource(t, pool, nsID, "oci_registry", "ghcr")
	uploadSrc := seedSource(t, pool, nsID, "upload", "ci")

	// An image scanned by a tool that recorded no location — which is also the
	// shape of every SBOM ingested before component.file_path existed.
	ingestOK(t, srv.URL, ownerKey, "/api/v1/sboms?source="+registrySrc,
		cmdImageSBOM(3, "nopath", ""))

	ingestOK(t, srv.URL, ownerKey,
		cmdUploadPath(uploadSrc, "git-worker", ocidexModule, digestOf("binary-git-worker")),
		cmdBinarySBOM(3, "git-worker"))

	// A look-alike: same binary name, a module whose path merely begins with
	// the component's. A string prefix would match it; a path boundary must not.
	ingestOK(t, srv.URL, ownerKey,
		cmdUploadPath(uploadSrc, "git-worker", ocidexModule+"-extra", digestOf("binary-git-worker-extra")),
		cmdBinarySBOM(4, "git-worker"))

	noPathImageID := artifactIDByName(t, pool, "ghcr.io/pfenerty/ocidex-nopath")

	// R7: an unknown path is no match, rather than a match against every
	// command of the module. The failure mode is the status quo.
	is.Equal(len(fetchRelations(t, srv.URL, ownerKey, noPathImageID, "contains")), 0)

	// With a path recorded, the command under the module matches and the
	// look-alike under the longer module does not.
	ingestOK(t, srv.URL, ownerKey, "/api/v1/sboms?source="+registrySrc,
		cmdImageSBOM(5, "git-worker", "/git-worker"))

	gitImageID := artifactIDByName(t, pool, "ghcr.io/pfenerty/ocidex-git-worker")
	contains := fetchRelations(t, srv.URL, ownerKey, gitImageID, "contains")
	is.Equal(len(contains), 1)
	is.Equal(contains[0].ArtifactID, artifactIDByNameGroup(t, pool, "git-worker", ocidexModule))
}
