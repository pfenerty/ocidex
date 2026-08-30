package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/matryer/is"
)

// dirScanSBOM is the shape syft emits for `syft dir:.sbom-bins`: the subject is
// the scratch directory that was scanned, with no purl and no useful name.
//
// This is the whole reason the declared-subject parameters exist — an SBOM built
// this way cannot identify what it describes, so the pusher has to say.
const dirScanSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:5f3c9a10-2c11-4a55-9d21-8c0a7e6b4411",
	"metadata": {
		"component": {"type": "file", "name": ".sbom-bins"}
	},
	"components": [
		{"type": "library", "name": "github.com/spf13/cobra", "version": "v1.10.2", "purl": "pkg:golang/github.com/spf13/cobra@v1.10.2"},
		{"type": "library", "name": "github.com/google/uuid", "version": "v1.6.0", "purl": "pkg:golang/github.com/google/uuid@v1.6.0"}
	]
}`

// buildCLI compiles cmd/ocidex-cli and returns the binary's path.
//
// Running the real binary rather than calling the push function directly is the
// point: CI reads the process exit code, and a command that returned an error
// but exited 0 would publish nothing while looking like a success.
func buildCLI(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ocidex-cli")
	out, err := exec.CommandContext(t.Context(),
		"go", "build", "-o", path, "../cmd/ocidex-cli").CombinedOutput()
	if err != nil {
		t.Fatalf("building ocidex-cli: %v: %s", err, out)
	}
	return path
}

// runCLI executes the CLI with the given API key and returns its combined
// output and exit code.
func runCLI(t *testing.T, bin, apiKey string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, args...)
	cmd.Env = append(os.Environ(), "OCIDEX_API_KEY="+apiKey)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exitErr):
		return string(out), exitErr.ExitCode()
	default:
		t.Fatalf("running ocidex-cli: %v: %s", err, out)
		return "", 0
	}
}

// TestCLIPush is the end-to-end upload path: a directory-scan SBOM plus a
// built artifact, pushed by the real binary into a namespace the caller owns.
func TestCLIPush(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)

	memberID := seedUser(t, pool, 9401, "cli-push-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "cli-push", nil)
	is.NoErr(err)

	nsName := "cli-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	nsID := seedNamespace(t, pool, nsName, memberID, "public")
	seedSource(t, pool, nsID, "upload", "ci")

	// A namespace the member does not own, for the 403 case.
	otherID := seedUser(t, pool, 9402, "cli-push-other", "member")
	otherNS := "other-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	seedSource(t, pool, seedNamespace(t, pool, otherNS, otherID, "public"), "upload", "ci")

	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "ocidex.cdx.json")
	binPath := filepath.Join(dir, "ocidex")
	binBytes := []byte("pretend this is ./bin/ocidex")
	is.NoErr(os.WriteFile(sbomPath, []byte(dirScanSBOM), 0o600))
	is.NoErr(os.WriteFile(binPath, binBytes, 0o600))

	bin := buildCLI(t)
	push := func(source string) (string, int) {
		return runCLI(t, bin, memberKey, "sbom", "push", sbomPath,
			"--server", srv.URL,
			"--source", source,
			"--artifact-file", binPath,
			"--subject-type", "application",
			"--subject-name", "ocidex",
			"--subject-group", "github.com/pfenerty",
			"--subject-purl", "pkg:golang/github.com/pfenerty/ocidex@v1.2.3",
			"--version", "v1.2.3",
		)
	}

	out, code := push(nsName + "/ci")
	if code != 0 {
		t.Fatalf("push failed (exit %d): %s", code, out)
	}
	sbomID := strings.Fields(strings.TrimSpace(out))[0]

	// The stored SBOM carries the declared identity, and the digest is the
	// sha256 of the artifact file rather than of the SBOM document.
	resp, err := doWithAuth(t, http.MethodGet, srv.URL+"/api/v1/sboms/"+sbomID, "", memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var detail struct {
		Digest         string `json:"digest"`
		SubjectVersion string `json:"subjectVersion"`
		ArtifactID     string `json:"artifactId"`
	}
	is.NoErr(json.NewDecoder(resp.Body).Decode(&detail))
	resp.Body.Close()

	sum := sha256.Sum256(binBytes)
	is.Equal(detail.Digest, "sha256:"+hex.EncodeToString(sum[:]))
	is.Equal(detail.SubjectVersion, "v1.2.3")

	// The artifact is the declared subject, not the ".sbom-bins" directory the
	// BOM's own metadata.component names.
	resp, err = doWithAuth(t, http.MethodGet, srv.URL+"/api/v1/artifacts/"+detail.ArtifactID, "", memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	var artifact struct {
		Name  string  `json:"name"`
		Type  string  `json:"type"`
		Group *string `json:"group"`
		Purl  *string `json:"purl"`
	}
	is.NoErr(json.NewDecoder(resp.Body).Decode(&artifact))
	resp.Body.Close()

	is.Equal(artifact.Name, "ocidex")
	is.Equal(artifact.Type, "application")
	is.True(artifact.Group != nil && *artifact.Group == "github.com/pfenerty")
	is.True(artifact.Purl != nil && *artifact.Purl == "pkg:golang/github.com/pfenerty/ocidex@v1.2.3")

	// Pushing into someone else's namespace fails loudly.
	out, code = push(otherNS + "/ci")
	is.True(code != 0)
	is.True(strings.Contains(out, "forbidden"))

	// So does a source that cannot be resolved at all.
	_, code = push(nsName + "/nope")
	is.True(code != 0)
}
