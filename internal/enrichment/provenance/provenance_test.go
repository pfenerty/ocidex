package provenance

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/enrichment"
)

// ----- test fixtures ---------------------------------------------------------

const testImageDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

var (
	fakeSigPayload       = []byte(`{"critical":{"identity":{"docker-reference":"example.com/repo"},"image":{"docker-manifest-digest":"` + testImageDigest + `"},"type":"cosign container image signature"},"optional":null}`)
	fakeAttPayload       = []byte(`{"payload":"dGVzdA==","payloadType":"application/vnd.in-toto+json","signatures":[]}`)
	fakeRawInTotoPayload = []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"example.com/repo","digest":{"sha256":"0000000000000000000000000000000000000000000000000000000000000001"}}],"predicate":{"buildDefinition":{"resolvedDependencies":[{"uri":"git+https://github.com/example/repo","digest":{"sha1":"abc123"}}]},"runDetails":{"builder":{"id":"https://buildkit.moby.dev"},"metadata":{}}}}`)
	fakeConfig           = []byte(`{}`)

	// fakeSigstoreBundlePayload wraps the same in-toto statement as
	// fakeRawInTotoPayload inside a Sigstore Bundle's dsseEnvelope, matching the
	// real shape published by e.g. ghcr.io/dexidp/dex.
	fakeSigstoreBundlePayload = []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{},"dsseEnvelope":{"payload":"` +
		base64.StdEncoding.EncodeToString(fakeRawInTotoPayload) +
		`","payloadType":"application/vnd.in-toto+json","signatures":[]}}`)
)

func digestOf(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h[:])
}

// buildManifest returns OCI manifest JSON and its digest for a single-layer cosign artifact.
func buildManifest(layerMediaType, layerDigest string, layerSize int, configDigest string, annotations map[string]string) ([]byte, string) {
	annoJSON := "{}"
	if len(annotations) > 0 {
		b, _ := json.Marshal(annotations)
		annoJSON = string(b)
	}
	manifest := fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.dev.cosign.config.v1+json","size":%d,"digest":"%s"},"layers":[{"mediaType":"%s","size":%d,"digest":"%s"}],"annotations":%s}`,
		len(fakeConfig), configDigest,
		layerMediaType, layerSize, layerDigest,
		annoJSON,
	)
	return []byte(manifest), digestOf([]byte(manifest))
}

// buildReferrersIndex returns OCI index JSON for a referrers index with both sig and att entries.
func buildReferrersIndex(sigDigest string, sigSize int, attDigest string, attSize int) []byte {
	idx := fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%d,"artifactType":"application/vnd.dev.cosign.artifact.sig.v1+json"},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%d,"artifactType":"application/vnd.dsse.envelope.v1+json"}]}`,
		sigDigest, sigSize, attDigest, attSize,
	)
	return []byte(idx)
}

// buildSigOnlyReferrersIndex returns a referrers index containing only a signature entry.
func buildSigOnlyReferrersIndex(sigDigest string, sigSize int) []byte {
	return []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%d,"artifactType":"application/vnd.dev.cosign.artifact.sig.v1+json"}]}`,
		sigDigest, sigSize,
	))
}

// buildAttOnlyReferrersIndex returns a referrers index containing only an attestation entry.
func buildAttOnlyReferrersIndex(attDigest string, attSize int) []byte {
	return []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%d,"artifactType":"application/vnd.dsse.envelope.v1+json"}]}`,
		attDigest, attSize,
	))
}

// buildRawInTotoReferrersIndex returns a referrers index with a buildkit-native in-toto entry.
func buildRawInTotoReferrersIndex(attDigest string, attSize int) []byte {
	return []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%d,"artifactType":"application/vnd.in-toto+json"}]}`,
		attDigest, attSize,
	))
}

// buildSigstoreBundleReferrersIndex returns a referrers index with a Sigstore Bundle entry.
func buildSigstoreBundleReferrersIndex(attDigest string, attSize int) []byte {
	return []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%d,"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json"}]}`,
		attDigest, attSize,
	))
}

// ----- test server helpers ---------------------------------------------------

type route struct {
	contentType string
	statusCode  int
	body        []byte
}

// newTestServer creates an httptest server that responds to the given path→route map.
// /v2/ always returns 200 for the auth probe.
func newTestServer(t *testing.T, routes map[string]route) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		// Auth probe
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Routes are keyed without the /v2 prefix.
		path := strings.TrimPrefix(r.URL.Path, "/v2")
		resp, ok := routes[path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if resp.contentType != "" {
			w.Header().Set("Content-Type", resp.contentType)
		}
		code := resp.statusCode
		if code == 0 {
			code = http.StatusOK
		}
		w.WriteHeader(code)
		_, _ = w.Write(resp.body)
	})
	return httptest.NewServer(mux)
}

func newTestEnricher(srv *httptest.Server) *Enricher {
	return NewEnricher(
		WithInsecure(),
		WithRemoteOptions(remote.WithTransport(srv.Client().Transport)),
		WithTimeout(5*time.Second),
	)
}

// testRef builds a SubjectRef pointing at the given host.
func testRef(host string) enrichment.SubjectRef {
	return enrichment.SubjectRef{
		ArtifactType: "container",
		ArtifactName: host + "/repo",
		Digest:       testImageDigest,
	}
}

// ----- discovery tests -------------------------------------------------------

func TestDiscoverViaReferrers(t *testing.T) {
	is := is.New(t)

	sigLayerDigest := digestOf(fakeSigPayload)
	attLayerDigest := digestOf(fakeAttPayload)
	configDigest := digestOf(fakeConfig)

	sigManifestBytes, sigManifestDigest := buildManifest(
		"application/vnd.dev.cosign.simplesigning.v1+json",
		sigLayerDigest, len(fakeSigPayload), configDigest,
		map[string]string{"dev.cosignproject.cosign/signature": "dGVzdHNpZw=="},
	)
	attManifestBytes, attManifestDigest := buildManifest(
		"application/vnd.dsse.envelope.v1+json",
		attLayerDigest, len(fakeAttPayload), configDigest,
		nil,
	)

	referrersIdx := buildReferrersIndex(sigManifestDigest, len(sigManifestBytes), attManifestDigest, len(attManifestBytes))

	hexDigest := strings.TrimPrefix(testImageDigest, "sha256:")
	repo := "/repo"

	routes := map[string]route{
		repo + "/referrers/sha256:" + hexDigest: {
			contentType: "application/vnd.oci.image.index.v1+json",
			body:        referrersIdx,
		},
		repo + "/manifests/" + sigManifestDigest: {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        sigManifestBytes,
		},
		repo + "/manifests/" + attManifestDigest: {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        attManifestBytes,
		},
		repo + "/blobs/" + sigLayerDigest: {body: fakeSigPayload},
		repo + "/blobs/" + attLayerDigest: {body: fakeAttPayload},
		repo + "/blobs/" + configDigest:   {body: fakeConfig},
	}

	srv := newTestServer(t, routes)
	defer srv.Close()

	e := newTestEnricher(srv)
	ref := testRef(strings.TrimPrefix(srv.URL, "http://"))

	data, err := e.Enrich(t.Context(), ref)
	is.NoErr(err)

	var result Provenance
	is.NoErr(json.Unmarshal(data, &result))

	is.True(result.SignaturePresent)
	is.True(result.AttestationPresent)
}

// TestDiscover_PrefersIndexDigest verifies that when a SubjectRef carries an
// IndexDigest (the per-platform SBOM was expanded from a multi-arch index),
// provenance is looked up on the index digest — where cosign/Tekton Chains sign —
// not on the child image digest. All routes are keyed on the index digest and the
// child digest is deliberately unserved; success proves the index digest was used.
func TestDiscover_PrefersIndexDigest(t *testing.T) {
	is := is.New(t)

	const indexDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000ab"
	const childDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000cd"

	sigLayerDigest := digestOf(fakeSigPayload)
	attLayerDigest := digestOf(fakeAttPayload)
	configDigest := digestOf(fakeConfig)

	sigManifestBytes, sigManifestDigest := buildManifest(
		"application/vnd.dev.cosign.simplesigning.v1+json",
		sigLayerDigest, len(fakeSigPayload), configDigest,
		map[string]string{"dev.cosignproject.cosign/signature": "dGVzdHNpZw=="},
	)
	attManifestBytes, attManifestDigest := buildManifest(
		"application/vnd.dsse.envelope.v1+json",
		attLayerDigest, len(fakeAttPayload), configDigest,
		nil,
	)

	referrersIdx := buildReferrersIndex(sigManifestDigest, len(sigManifestBytes), attManifestDigest, len(attManifestBytes))

	indexHex := strings.TrimPrefix(indexDigest, "sha256:")
	repo := "/repo"

	routes := map[string]route{
		// Served only for the index digest. The child digest has no routes.
		repo + "/referrers/sha256:" + indexHex: {
			contentType: "application/vnd.oci.image.index.v1+json",
			body:        referrersIdx,
		},
		repo + "/manifests/" + sigManifestDigest: {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        sigManifestBytes,
		},
		repo + "/manifests/" + attManifestDigest: {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        attManifestBytes,
		},
		repo + "/blobs/" + sigLayerDigest: {body: fakeSigPayload},
		repo + "/blobs/" + attLayerDigest: {body: fakeAttPayload},
		repo + "/blobs/" + configDigest:   {body: fakeConfig},
	}

	srv := newTestServer(t, routes)
	defer srv.Close()

	e := newTestEnricher(srv)
	ref := testRef(strings.TrimPrefix(srv.URL, "http://"))
	ref.Digest = childDigest      // the per-platform child (unsigned, unserved)
	ref.IndexDigest = indexDigest // where provenance actually lives

	data, err := e.Enrich(t.Context(), ref)
	is.NoErr(err)

	var result Provenance
	is.NoErr(json.Unmarshal(data, &result))

	is.True(result.SignaturePresent) // found via the index digest
	is.True(result.AttestationPresent)
}

func TestDiscoverViaTagScheme(t *testing.T) {
	is := is.New(t)

	sigLayerDigest := digestOf(fakeSigPayload)
	attLayerDigest := digestOf(fakeAttPayload)
	configDigest := digestOf(fakeConfig)

	sigManifestBytes, _ := buildManifest(
		"application/vnd.dev.cosign.simplesigning.v1+json",
		sigLayerDigest, len(fakeSigPayload), configDigest,
		map[string]string{"dev.cosignproject.cosign/signature": "dGVzdHNpZw=="},
	)
	attManifestBytes, _ := buildManifest(
		"application/vnd.dsse.envelope.v1+json",
		attLayerDigest, len(fakeAttPayload), configDigest,
		nil,
	)

	hexDigest := strings.TrimPrefix(testImageDigest, "sha256:")
	tagBase := "sha256-" + hexDigest
	repo := "/repo"

	routes := map[string]route{
		// Referrers endpoint not supported → 404 forces tag-scheme fallback.
		repo + "/referrers/sha256:" + hexDigest: {statusCode: http.StatusNotFound},
		// Also return 404 for the OCI spec's fallback tag (sha256-<hex> without .sig/.att).
		repo + "/manifests/sha256-" + hexDigest: {statusCode: http.StatusNotFound},

		// Cosign tag scheme.
		repo + "/manifests/" + tagBase + ".sig": {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        sigManifestBytes,
		},
		repo + "/manifests/" + tagBase + ".att": {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        attManifestBytes,
		},
		repo + "/blobs/" + sigLayerDigest: {body: fakeSigPayload},
		repo + "/blobs/" + attLayerDigest: {body: fakeAttPayload},
		repo + "/blobs/" + configDigest:   {body: fakeConfig},
	}

	srv := newTestServer(t, routes)
	defer srv.Close()

	e := newTestEnricher(srv)
	ref := testRef(strings.TrimPrefix(srv.URL, "http://"))

	data, err := e.Enrich(t.Context(), ref)
	is.NoErr(err)

	var result Provenance
	is.NoErr(json.Unmarshal(data, &result))

	is.True(result.SignaturePresent)
	is.True(result.AttestationPresent)
}

// TestDiscover_SigOnly verifies that a referrers index containing only a sig entry
// produces SignaturePresent=true and AttestationPresent=false without tag-scheme fallback.
func TestDiscover_SigOnly(t *testing.T) {
	is := is.New(t)

	sigLayerDigest := digestOf(fakeSigPayload)
	configDigest := digestOf(fakeConfig)

	sigManifestBytes, sigManifestDigest := buildManifest(
		"application/vnd.dev.cosign.simplesigning.v1+json",
		sigLayerDigest, len(fakeSigPayload), configDigest,
		map[string]string{"dev.cosignproject.cosign/signature": "dGVzdHNpZw=="},
	)

	hexDigest := strings.TrimPrefix(testImageDigest, "sha256:")
	repo := "/repo"

	routes := map[string]route{
		repo + "/referrers/sha256:" + hexDigest: {
			contentType: "application/vnd.oci.image.index.v1+json",
			body:        buildSigOnlyReferrersIndex(sigManifestDigest, len(sigManifestBytes)),
		},
		repo + "/manifests/" + sigManifestDigest: {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        sigManifestBytes,
		},
		repo + "/blobs/" + sigLayerDigest: {body: fakeSigPayload},
		repo + "/blobs/" + configDigest:   {body: fakeConfig},
	}

	srv := newTestServer(t, routes)
	defer srv.Close()

	e := newTestEnricher(srv)
	ref := testRef(strings.TrimPrefix(srv.URL, "http://"))

	data, err := e.Enrich(t.Context(), ref)
	is.NoErr(err)

	var result Provenance
	is.NoErr(json.Unmarshal(data, &result))

	is.True(result.SignaturePresent)
	is.True(!result.AttestationPresent)
}

// TestDiscover_AttOnly verifies that a referrers index containing only an att entry
// produces AttestationPresent=true and SignaturePresent=false.
func TestDiscover_AttOnly(t *testing.T) {
	is := is.New(t)

	attLayerDigest := digestOf(fakeAttPayload)
	configDigest := digestOf(fakeConfig)

	attManifestBytes, attManifestDigest := buildManifest(
		"application/vnd.dsse.envelope.v1+json",
		attLayerDigest, len(fakeAttPayload), configDigest,
		nil,
	)

	hexDigest := strings.TrimPrefix(testImageDigest, "sha256:")
	repo := "/repo"

	routes := map[string]route{
		repo + "/referrers/sha256:" + hexDigest: {
			contentType: "application/vnd.oci.image.index.v1+json",
			body:        buildAttOnlyReferrersIndex(attManifestDigest, len(attManifestBytes)),
		},
		repo + "/manifests/" + attManifestDigest: {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        attManifestBytes,
		},
		repo + "/blobs/" + attLayerDigest: {body: fakeAttPayload},
		repo + "/blobs/" + configDigest:   {body: fakeConfig},
	}

	srv := newTestServer(t, routes)
	defer srv.Close()

	e := newTestEnricher(srv)
	ref := testRef(strings.TrimPrefix(srv.URL, "http://"))

	data, err := e.Enrich(t.Context(), ref)
	is.NoErr(err)

	var result Provenance
	is.NoErr(json.Unmarshal(data, &result))

	is.True(!result.SignaturePresent)
	is.True(result.AttestationPresent)
}

// TestDiscover_RawInToto verifies that a referrers index with application/vnd.in-toto+json
// (buildkit native) produces AttestationPresent=true and populates provenance fields.
func TestDiscover_RawInToto(t *testing.T) {
	is := is.New(t)

	attLayerDigest := digestOf(fakeRawInTotoPayload)
	configDigest := digestOf(fakeConfig)

	attManifestBytes, attManifestDigest := buildManifest(
		"application/vnd.in-toto+json",
		attLayerDigest, len(fakeRawInTotoPayload), configDigest,
		nil,
	)

	hexDigest := strings.TrimPrefix(testImageDigest, "sha256:")
	repo := "/repo"

	routes := map[string]route{
		repo + "/referrers/sha256:" + hexDigest: {
			contentType: "application/vnd.oci.image.index.v1+json",
			body:        buildRawInTotoReferrersIndex(attManifestDigest, len(attManifestBytes)),
		},
		repo + "/manifests/" + attManifestDigest: {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        attManifestBytes,
		},
		repo + "/blobs/" + attLayerDigest: {body: fakeRawInTotoPayload},
		repo + "/blobs/" + configDigest:   {body: fakeConfig},
	}

	srv := newTestServer(t, routes)
	defer srv.Close()

	e := newTestEnricher(srv)
	ref := testRef(strings.TrimPrefix(srv.URL, "http://"))

	data, err := e.Enrich(t.Context(), ref)
	is.NoErr(err)

	var result Provenance
	is.NoErr(json.Unmarshal(data, &result))

	is.True(!result.SignaturePresent)
	is.True(result.AttestationPresent)
	is.Equal(result.PredicateType, "https://slsa.dev/provenance/v1")
	is.Equal(result.BuilderID, "https://buildkit.moby.dev")
	is.Equal(len(result.Subjects), 1)
	is.Equal(result.SourceURI, "https://github.com/example/repo")
	is.Equal(result.SourceCommit, "abc123")
}

// TestDiscover_SigstoreBundle verifies that a referrers index with
// application/vnd.dev.sigstore.bundle.v0.3+json produces AttestationPresent=true
// and populates provenance fields from the nested DSSE envelope.
func TestDiscover_SigstoreBundle(t *testing.T) {
	is := is.New(t)

	attLayerDigest := digestOf(fakeSigstoreBundlePayload)
	configDigest := digestOf(fakeConfig)

	attManifestBytes, attManifestDigest := buildManifest(
		"application/vnd.dev.sigstore.bundle.v0.3+json",
		attLayerDigest, len(fakeSigstoreBundlePayload), configDigest,
		nil,
	)

	hexDigest := strings.TrimPrefix(testImageDigest, "sha256:")
	repo := "/repo"

	routes := map[string]route{
		repo + "/referrers/sha256:" + hexDigest: {
			contentType: "application/vnd.oci.image.index.v1+json",
			body:        buildSigstoreBundleReferrersIndex(attManifestDigest, len(attManifestBytes)),
		},
		repo + "/manifests/" + attManifestDigest: {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        attManifestBytes,
		},
		repo + "/blobs/" + attLayerDigest: {body: fakeSigstoreBundlePayload},
		repo + "/blobs/" + configDigest:   {body: fakeConfig},
	}

	srv := newTestServer(t, routes)
	defer srv.Close()

	e := newTestEnricher(srv)
	ref := testRef(strings.TrimPrefix(srv.URL, "http://"))

	data, err := e.Enrich(t.Context(), ref)
	is.NoErr(err)

	var result Provenance
	is.NoErr(json.Unmarshal(data, &result))

	is.True(!result.SignaturePresent)
	is.True(result.AttestationPresent)
	is.Equal(result.PredicateType, "https://slsa.dev/provenance/v1")
	is.Equal(result.BuilderID, "https://buildkit.moby.dev")
	is.Equal(len(result.Subjects), 1)
	is.Equal(result.SourceURI, "https://github.com/example/repo")
	is.Equal(result.SourceCommit, "abc123")
}

// TestDiscover_NoAnchor verifies that when both referrers and tag-scheme lookups return 404
// the enricher returns a nil error and a zero-value Provenance.
func TestDiscover_NoAnchor(t *testing.T) {
	is := is.New(t)

	hexDigest := strings.TrimPrefix(testImageDigest, "sha256:")
	tagBase := "sha256-" + hexDigest
	repo := "/repo"

	routes := map[string]route{
		repo + "/referrers/sha256:" + hexDigest: {statusCode: http.StatusNotFound},
		repo + "/manifests/sha256-" + hexDigest: {statusCode: http.StatusNotFound},
		repo + "/manifests/" + tagBase + ".sig": {statusCode: http.StatusNotFound},
		repo + "/manifests/" + tagBase + ".att": {statusCode: http.StatusNotFound},
	}

	srv := newTestServer(t, routes)
	defer srv.Close()

	e := newTestEnricher(srv)
	ref := testRef(strings.TrimPrefix(srv.URL, "http://"))

	data, err := e.Enrich(t.Context(), ref)
	is.NoErr(err)

	var result Provenance
	is.NoErr(json.Unmarshal(data, &result))

	is.True(!result.SignaturePresent)
	is.True(!result.AttestationPresent)
}

// ----- CanEnrich / Name -------------------------------------------------------

func TestCanEnrich(t *testing.T) {
	is := is.New(t)
	e := NewEnricher()

	is.True(e.CanEnrich(enrichment.SubjectRef{ArtifactType: "container", Digest: "sha256:abc"}))
	is.True(!e.CanEnrich(enrichment.SubjectRef{ArtifactType: "container"}))                  // missing digest
	is.True(!e.CanEnrich(enrichment.SubjectRef{ArtifactType: "file", Digest: "sha256:abc"})) // wrong type
}

func TestName(t *testing.T) {
	is := is.New(t)
	is.Equal(NewEnricher().Name(), "provenance")
}

// ----- parse tests ------------------------------------------------------------

// TestBuildProvenance is a table-driven test for buildProvenance across all named edge cases.
func TestBuildProvenance(t *testing.T) {
	sigLayer, err := os.ReadFile("testdata/sig_layer.json")
	if err != nil {
		t.Fatal(err)
	}
	attLayer, err := os.ReadFile("testdata/att_layer.json")
	if err != nil {
		t.Fatal(err)
	}
	annoBytes, err := os.ReadFile("testdata/sig_annotations.json")
	if err != nil {
		t.Fatal(err)
	}
	var annotations map[string]string
	if err := json.Unmarshal(annoBytes, &annotations); err != nil {
		t.Fatal(err)
	}

	expectedStartedOn := time.Date(2026, 6, 22, 19, 24, 26, 0, time.UTC)

	cases := []struct {
		name  string
		raw   RawArtifacts
		check func(*testing.T, Provenance)
	}{
		{
			name: "valid",
			raw: RawArtifacts{
				SigPresent:     true,
				SigLayerBytes:  sigLayer,
				SigAnnotations: annotations,
				AttPresent:     true,
				AttLayerBytes:  attLayer,
			},
			check: func(t *testing.T, p Provenance) {
				is := is.New(t)
				is.True(p.SignaturePresent)
				is.True(p.AttestationPresent)
				is.Equal(p.PredicateType, "https://slsa.dev/provenance/v1")
				is.Equal(p.BuilderID, "https://tekton.dev/chains/v2")
				is.Equal(p.SignerFingerprint, "SHA256:KLoB48wClIeVK6tEP+oWoDjf1jA9WIEf86lrYOr93RU")
				is.Equal(len(p.Subjects), 7)
				is.True(p.BuildStartedOn != nil)
				is.Equal(p.BuildStartedOn.UTC(), expectedStartedOn)
			},
		},
		{
			name: "sig_only",
			raw: RawArtifacts{
				SigPresent:     true,
				SigLayerBytes:  sigLayer,
				SigAnnotations: annotations,
				AttPresent:     false,
			},
			check: func(t *testing.T, p Provenance) {
				is := is.New(t)
				is.True(p.SignaturePresent)
				is.True(!p.AttestationPresent)
				is.Equal(p.BuilderID, "")
				is.Equal(p.PredicateType, "")
				is.True(p.BuildStartedOn == nil)
				is.Equal(len(p.Subjects), 0)
			},
		},
		{
			name: "att_only",
			raw: RawArtifacts{
				SigPresent:    false,
				AttPresent:    true,
				AttLayerBytes: attLayer,
			},
			check: func(t *testing.T, p Provenance) {
				is := is.New(t)
				is.True(!p.SignaturePresent)
				is.True(p.AttestationPresent)
				is.Equal(p.BuilderID, "https://tekton.dev/chains/v2")
				is.Equal(p.PredicateType, "https://slsa.dev/provenance/v1")
				is.Equal(len(p.Subjects), 7)
				// No sig annotations → no RekorLogIndex
				is.Equal(p.RekorLogIndex, int64(0))
			},
		},
		{
			name: "no_anchor",
			raw:  RawArtifacts{},
			check: func(t *testing.T, p Provenance) {
				is := is.New(t)
				is.True(!p.SignaturePresent)
				is.True(!p.AttestationPresent)
				is.Equal(p.BuilderID, "")
				is.Equal(p.PredicateType, "")
				is.Equal(p.SignerFingerprint, "")
				is.True(p.BuildStartedOn == nil)
				is.Equal(len(p.Subjects), 0)
				is.Equal(p.RekorLogIndex, int64(0))
				is.True(p.Verified == nil)
			},
		},
		{
			name: "malformed_att",
			raw: RawArtifacts{
				AttPresent:    true,
				AttLayerBytes: []byte("not valid json"),
			},
			check: func(t *testing.T, p Provenance) {
				is := is.New(t)
				// Flag is taken from RawArtifacts directly; parse failure is silent.
				is.True(p.AttestationPresent)
				is.Equal(p.BuilderID, "")
				is.Equal(p.PredicateType, "")
				is.Equal(len(p.Subjects), 0)
			},
		},
		{
			name: "raw_intoto",
			raw: RawArtifacts{
				AttPresent:      true,
				AttLayerBytes:   fakeRawInTotoPayload,
				AttArtifactType: inTotoArtifactType,
			},
			check: func(t *testing.T, p Provenance) {
				is := is.New(t)
				is.True(!p.SignaturePresent)
				is.True(p.AttestationPresent)
				is.Equal(p.PredicateType, "https://slsa.dev/provenance/v1")
				is.Equal(p.BuilderID, "https://buildkit.moby.dev")
				is.Equal(len(p.Subjects), 1)
				is.Equal(p.SourceURI, "https://github.com/example/repo")
				is.Equal(p.SourceCommit, "abc123")
			},
		},
		{
			name: "sigstore_bundle",
			raw: RawArtifacts{
				AttPresent:      true,
				AttLayerBytes:   fakeSigstoreBundlePayload,
				AttArtifactType: bundleArtifactType,
			},
			check: func(t *testing.T, p Provenance) {
				is := is.New(t)
				is.True(!p.SignaturePresent)
				is.True(p.AttestationPresent)
				is.Equal(p.PredicateType, "https://slsa.dev/provenance/v1")
				is.Equal(p.BuilderID, "https://buildkit.moby.dev")
				is.Equal(len(p.Subjects), 1)
				is.Equal(p.SourceURI, "https://github.com/example/repo")
				is.Equal(p.SourceCommit, "abc123")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := buildProvenance(tc.raw)
			tc.check(t, p)
		})
	}
}

// ----- verification tests -----------------------------------------------------

// TestVerification is a table-driven test for applyVerification across all named cases.
func TestVerification(t *testing.T) {
	sigLayer, err := os.ReadFile("testdata/sig_layer.json")
	if err != nil {
		t.Fatal(err)
	}
	attLayer, err := os.ReadFile("testdata/att_layer.json")
	if err != nil {
		t.Fatal(err)
	}
	annoBytes, err := os.ReadFile("testdata/sig_annotations.json")
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPEM, err := os.ReadFile("testdata/cosign.pub")
	if err != nil {
		t.Fatal(err)
	}

	var annotations map[string]string
	if err := json.Unmarshal(annoBytes, &annotations); err != nil {
		t.Fatal(err)
	}

	baseRaw := RawArtifacts{
		SigPresent:     true,
		SigLayerBytes:  sigLayer,
		SigAnnotations: annotations,
		AttPresent:     true,
		AttLayerBytes:  attLayer,
	}

	boolPtr := func(v bool) *bool { return &v }

	// fixtureDigest is the image the testdata sig/att are bound to
	// (sig critical.image.docker-manifest-digest and att subject[0]).
	const fixtureDigest = "sha256:770d5a878241e8bbe8df521b3d21bcfe1a9603dfc10b28ff2493fef5d73aca77"

	cases := []struct {
		name         string
		mode         string
		pemKey       string
		imageDigest  string                          // "" defaults to fixtureDigest
		rawOverride  func(RawArtifacts) RawArtifacts // nil = use baseRaw as-is
		wantVerified *bool                           // nil means expect p.Verified == nil
	}{
		{
			name:         "valid_key",
			mode:         "public_key",
			pemKey:       string(pubKeyPEM),
			wantVerified: boolPtr(true),
		},
		{
			name:         "mode_none",
			mode:         "none",
			pemKey:       string(pubKeyPEM),
			wantVerified: nil,
		},
		{
			name:   "tampered",
			mode:   "public_key",
			pemKey: string(pubKeyPEM),
			rawOverride: func(r RawArtifacts) RawArtifacts {
				tampered := make(map[string]string, len(r.SigAnnotations))
				for k, v := range r.SigAnnotations {
					tampered[k] = v
				}
				tampered["dev.cosignproject.cosign/signature"] = "aGVsbG8=" // "hello" — invalid sig
				r.SigAnnotations = tampered
				return r
			},
			wantVerified: boolPtr(false),
		},
		{
			// invalid PEM: parsePEMPublicKey returns error → applyVerification exits early → Verified stays nil
			name:         "invalid_pem",
			mode:         "public_key",
			pemKey:       "notapemblock",
			wantVerified: nil,
		},
		{
			// F1: signature is valid against the key but is bound to a different
			// image digest (transplant attack) → must NOT verify.
			name:         "digest_mismatch",
			mode:         "public_key",
			pemKey:       string(pubKeyPEM),
			imageDigest:  "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			wantVerified: boolPtr(false),
		},
		{
			// F2: an asserted attestation that cannot be parsed must downgrade,
			// not be silently skipped.
			name:   "garbage_att",
			mode:   "public_key",
			pemKey: string(pubKeyPEM),
			rawOverride: func(r RawArtifacts) RawArtifacts {
				r.AttLayerBytes = []byte("not json")
				return r
			},
			wantVerified: boolPtr(false),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			raw := baseRaw
			if tc.rawOverride != nil {
				raw = tc.rawOverride(raw)
			}
			digest := tc.imageDigest
			if digest == "" {
				digest = fixtureDigest
			}
			p := buildProvenance(raw)
			applyVerification(&p, raw, tc.mode, tc.pemKey, digest)
			if tc.wantVerified == nil {
				is.True(p.Verified == nil)
			} else {
				is.True(p.Verified != nil)
				is.Equal(*p.Verified, *tc.wantVerified)
			}
		})
	}
}

// ----- Rekor UUID fetch tests ------------------------------------------------

func TestFetchRekorUUID(t *testing.T) {
	is := is.New(t)
	const wantUUID = "3e1b9f2a0c4d5678901234567890abcdef1234567890abcdef1234567890abcd"

	cases := []struct {
		name     string
		handler  http.HandlerFunc
		wantUUID string
	}{
		{
			name: "returns_uuid",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{%q:{}}`, wantUUID)
			},
			wantUUID: wantUUID,
		},
		{
			name: "not_found",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r)
			},
			wantUUID: "",
		},
		{
			name: "malformed_json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `not json`)
			},
			wantUUID: "",
		},
		{
			name: "empty_map",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `{}`)
			},
			wantUUID: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			// Patch the URL by building the request against the test server.
			// fetchRekorUUID uses the hardcoded Rekor URL, so we test the
			// helper via a thin wrapper that substitutes the base URL.
			got := fetchRekorUUIDFromBase(t.Context(), srv.URL, 42)
			is.Equal(got, tc.wantUUID)
		})
	}

	// Confirm buildProvenance alone does NOT set RekorUUID (fetch happens in Enrich).
	t.Run("buildProvenance_does_not_fetch", func(t *testing.T) {
		is := is.New(t)
		raw := RawArtifacts{
			SigPresent: true,
			SigAnnotations: map[string]string{
				"chains.tekton.dev/transparency": "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=9999",
			},
		}
		p := buildProvenance(raw)
		is.Equal(p.RekorLogIndex, int64(9999))
		is.Equal(p.RekorUUID, "") // not set by buildProvenance
	})
}
