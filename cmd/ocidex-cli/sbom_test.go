package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matryer/is"
)

const testSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"components": [{"type": "library", "name": "lib", "version": "1.0.0"}]
}`

// ingestStub is an ingest endpoint that records what it was sent.
type ingestStub struct {
	srv    *httptest.Server
	query  url.Values
	body   []byte
	status int // response status; 0 means 201
}

// newIngestStub starts a stub answering with status (or 201 when zero).
func newIngestStub(t *testing.T, status int) *ingestStub {
	t.Helper()
	// Point config resolution at an empty directory so the developer's own
	// ~/.config/ocidex/config.yaml cannot supply a server or an API key.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	s := &ingestStub{status: status}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *ingestStub) serve(w http.ResponseWriter, r *http.Request) {
	s.query = r.URL.Query()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r.Body)
	s.body = buf.Bytes()

	if s.status == 0 {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"11111111-1111-1111-1111-111111111111","status":"accepted","specVersion":"1.6","componentCount":1}`))
		return
	}
	w.WriteHeader(s.status)
	_, _ = w.Write([]byte(`{"detail":"sbom ingest requires a source"}`))
}

// push executes `sbom push` against the stub and returns anything it printed.
func (s *ingestStub) push(args ...string) (string, error) {
	out := &bytes.Buffer{}
	cmd, _ := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs(append([]string{"sbom", "push", "--server", s.srv.URL}, args...))
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// writeFiles drops an SBOM and an artifact into a temp dir and returns both paths.
func writeFiles(t *testing.T) (sbomPath, artifactPath string) {
	t.Helper()
	dir := t.TempDir()
	sbomPath = filepath.Join(dir, "ocidex.cdx.json")
	artifactPath = filepath.Join(dir, "ocidex")
	if err := os.WriteFile(sbomPath, []byte(testSBOM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("ELF-ish bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	return sbomPath, artifactPath
}

// TestSBOMPush_DeclaredSubject is the end-to-end shape CI uses: a syft SBOM for
// a built binary, pushed with the subject declared and the digest taken from the
// binary rather than from the SBOM.
func TestSBOMPush_DeclaredSubject(t *testing.T) {
	is := is.New(t)
	t.Setenv("OCIDEX_API_KEY", "ocidex_test")

	sbomPath, artifactPath := writeFiles(t)
	stub := newIngestStub(t, 0)

	out, err := stub.push(sbomPath,
		"--source", "myorg/ci",
		"--artifact-file", artifactPath,
		"--subject-type", "application",
		"--subject-name", "ocidex",
		"--subject-purl", "pkg:golang/github.com/pfenerty/ocidex@v1.2.3",
		"--version", "v1.2.3",
		"--arch", "amd64",
	)
	is.NoErr(err)

	sum := sha256.Sum256([]byte("ELF-ish bytes"))
	is.Equal(stub.query.Get("digest"), "sha256:"+hex.EncodeToString(sum[:]))
	is.Equal(stub.query.Get("source"), "myorg/ci")
	is.Equal(stub.query.Get("subject_type"), "application")
	is.Equal(stub.query.Get("subject_name"), "ocidex")
	is.Equal(stub.query.Get("subject_purl"), "pkg:golang/github.com/pfenerty/ocidex@v1.2.3")
	is.Equal(stub.query.Get("version"), "v1.2.3")
	// Architecture is what the sufficiency gate looks for; without it a
	// non-container SBOM only becomes visible via the relaxed type-aware rule.
	is.Equal(stub.query.Get("architecture"), "amd64")
	// The SBOM body goes up untouched.
	is.Equal(string(stub.body), testSBOM)
	// The new SBOM's id is printed so CI can capture it.
	is.True(strings.Contains(out, "11111111-1111-1111-1111-111111111111"))
}

// TestSBOMPush_ValueFilesDeclareSubject covers the same declared-subject shape as
// above, but with version and architecture arriving on disk instead of on the
// command line — how the sbom-push task feeds the distroless ocidex-cli image,
// which has no shell to compute them (ocidex-2u7y). Both files carry trailing
// newlines, because every way of writing them does.
func TestSBOMPush_ValueFilesDeclareSubject(t *testing.T) {
	is := is.New(t)
	t.Setenv("OCIDEX_API_KEY", "ocidex_test")

	sbomPath, artifactPath := writeFiles(t)
	dir := t.TempDir()
	versionPath := filepath.Join(dir, ".version")
	archPath := filepath.Join(dir, ".goarch")
	if err := os.WriteFile(versionPath, []byte("v1.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archPath, []byte("  amd64\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stub := newIngestStub(t, 0)
	_, err := stub.push(sbomPath,
		"--source", "myorg/ci",
		"--artifact-file", artifactPath,
		"--subject-type", "application",
		"--subject-name", "ocidex",
		"--version-file", versionPath,
		"--arch-file", archPath,
	)
	is.NoErr(err)

	is.Equal(stub.query.Get("version"), "v1.2.3")
	is.Equal(stub.query.Get("architecture"), "amd64")
}

// TestSBOMPush_ValidationFailures asserts the CLI exits non-zero rather than
// silently skipping the upload — CI treats a zero exit as "SBOM published".
func TestSBOMPush_ValidationFailures(t *testing.T) {
	sbomPath, artifactPath := writeFiles(t)

	emptyPath := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(emptyPath, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		apiKey string
		args   []string
		status int
	}{
		{
			// A bare name cannot be resolved: source names are unique per
			// namespace, not globally.
			name:   "bare source name",
			apiKey: "ocidex_test",
			args:   []string{sbomPath, "--source", "ci"},
		},
		{
			name:   "missing source",
			apiKey: "ocidex_test",
			args:   []string{sbomPath},
		},
		{
			name:   "no api key",
			apiKey: "",
			args:   []string{sbomPath, "--source", "myorg/ci"},
		},
		{
			name:   "sbom file missing",
			apiKey: "ocidex_test",
			args:   []string{filepath.Join(t.TempDir(), "nope.json"), "--source", "myorg/ci"},
		},
		{
			name:   "artifact file missing",
			apiKey: "ocidex_test",
			args:   []string{sbomPath, "--source", "myorg/ci", "--artifact-file", filepath.Join(t.TempDir(), "nope")},
		},
		{
			name:   "digest and artifact-file together",
			apiKey: "ocidex_test",
			args:   []string{sbomPath, "--source", "myorg/ci", "--artifact-file", artifactPath, "--digest", "sha256:abc"},
		},
		{
			name:   "version-file missing",
			apiKey: "ocidex_test",
			args:   []string{sbomPath, "--source", "myorg/ci", "--version-file", filepath.Join(t.TempDir(), "nope")},
		},
		{
			// Blank, not absent: build-binaries writing an empty file is the
			// failure mode that would otherwise push every binary versionless.
			name:   "version-file blank",
			apiKey: "ocidex_test",
			args:   []string{sbomPath, "--source", "myorg/ci", "--version-file", emptyPath},
		},
		{
			name:   "arch-file missing",
			apiKey: "ocidex_test",
			args:   []string{sbomPath, "--source", "myorg/ci", "--arch-file", filepath.Join(t.TempDir(), "nope")},
		},
		{
			name:   "version and version-file together",
			apiKey: "ocidex_test",
			args:   []string{sbomPath, "--source", "myorg/ci", "--version", "v1.2.3", "--version-file", emptyPath},
		},
		{
			name:   "arch and arch-file together",
			apiKey: "ocidex_test",
			args:   []string{sbomPath, "--source", "myorg/ci", "--arch", "amd64", "--arch-file", emptyPath},
		},
		{
			name:   "server rejects the request",
			apiKey: "ocidex_test",
			args:   []string{sbomPath, "--source", "myorg/ci"},
			status: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			t.Setenv("OCIDEX_API_KEY", tt.apiKey)
			_, err := newIngestStub(t, tt.status).push(tt.args...)
			is.True(err != nil)
		})
	}
}

func TestValidateSource(t *testing.T) {
	tests := []struct {
		source string
		ok     bool
	}{
		{"11111111-1111-1111-1111-111111111111", true},
		{"myorg/ci", true},
		{"ci", false},
		{"", false},
		{"myorg/", false},
		{"/ci", false},
		{"a/b/c", false},
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			is := is.New(t)
			is.Equal(validateSource(tt.source) == nil, tt.ok)
		})
	}
}
