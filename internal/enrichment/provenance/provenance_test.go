package provenance

import (
	"crypto/sha256"
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
	fakeSigPayload = []byte(`{"critical":{"identity":{"docker-reference":"example.com/repo"},"image":{"docker-manifest-digest":"` + testImageDigest + `"},"type":"cosign container image signature"},"optional":null}`)
	fakeAttPayload = []byte(`{"payload":"dGVzdA==","payloadType":"application/vnd.in-toto+json","signatures":[]}`)
	fakeConfig     = []byte(`{}`)
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

// buildReferrersIndex returns OCI index JSON for a referrers index with sig+att entries.
func buildReferrersIndex(sigDigest string, sigSize int, attDigest string, attSize int) []byte {
	idx := fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%d,"artifactType":"application/vnd.dev.cosign.artifact.sig.v1+json"},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%d,"artifactType":"application/vnd.dsse.envelope.v1+json"}]}`,
		sigDigest, sigSize, attDigest, attSize,
	)
	return []byte(idx)
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

// ----- tests -----------------------------------------------------------------

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

func TestCanEnrich(t *testing.T) {
	is := is.New(t)
	e := NewEnricher()

	is.True(e.CanEnrich(enrichment.SubjectRef{ArtifactType: "container", Digest: "sha256:abc"}))
	is.True(!e.CanEnrich(enrichment.SubjectRef{ArtifactType: "container"}))       // missing digest
	is.True(!e.CanEnrich(enrichment.SubjectRef{ArtifactType: "file", Digest: "sha256:abc"})) // wrong type
}

func TestName(t *testing.T) {
	is := is.New(t)
	is.Equal(NewEnricher().Name(), "provenance")
}

func TestParseRealFixtures(t *testing.T) {
	is := is.New(t)

	sigLayer, err := os.ReadFile("testdata/sig_layer.json")
	is.NoErr(err)
	attLayer, err := os.ReadFile("testdata/att_layer.json")
	is.NoErr(err)
	annoBytes, err := os.ReadFile("testdata/sig_annotations.json")
	is.NoErr(err)

	var annotations map[string]string
	is.NoErr(json.Unmarshal(annoBytes, &annotations))

	raw := RawArtifacts{
		SigPresent:     true,
		SigLayerBytes:  sigLayer,
		SigAnnotations: annotations,
		AttPresent:     true,
		AttLayerBytes:  attLayer,
	}

	p := buildProvenance(raw)

	is.True(p.SignaturePresent)
	is.True(p.AttestationPresent)
	is.Equal(p.PredicateType, "https://slsa.dev/provenance/v1")
	is.True(p.BuilderID != "")
	is.True(len(p.Subjects) > 0)
	is.True(p.SignerFingerprint != "")
	is.True(p.BuildStartedOn != nil)
}
