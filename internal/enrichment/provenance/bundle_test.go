package provenance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"google.golang.org/protobuf/proto"

	"github.com/pfenerty/ocidex/internal/trust"
)

// ----- classification --------------------------------------------------------
//
// cosign's new bundle format publishes signatures and attestations under the
// same OCI artifact type, and quay.io/cilium/cilium ships both on one image.
// Routing every bundle to Atts made 96 correctly signed SBOMs read as
// attestation-only, and then fail verification (ocidex-gm28).

// buildTwoBundleReferrersIndex returns a referrers index naming two Sigstore
// bundle referrers, the shape cilium publishes.
func buildTwoBundleReferrersIndex(firstDigest string, firstSize int, secondDigest string, secondSize int) []byte {
	const entry = `{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%d,"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`
	return []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[`+entry+`,`+entry+`]}`,
		firstDigest, firstSize, secondDigest, secondSize,
	))
}

// TestDiscover_BundleSignatureAndAttestation is the ocidex-gm28 regression, with
// the upstream lie intact: both referrer manifests carry
// dev.sigstore.bundle.predicateType: .../cosign/sign/v1, including the one whose
// DSSE payload is an SPDX document. Anything reading that annotation classifies
// both the same way; only the payload separates them.
//
// The two fixtures are the real cilium bundles (the SPDX one with its 5 MB
// predicate trimmed out), so this also proves the classifier survives the shape
// a live registry actually serves.
func TestDiscover_BundleSignatureAndAttestation(t *testing.T) {
	is := is.New(t)

	sigBundle, err := os.ReadFile("testdata/bundle_sig_layer.json")
	is.NoErr(err)
	attBundle, err := os.ReadFile("testdata/bundle_att_layer.json")
	is.NoErr(err)

	// The annotation both referrers carry upstream — and which must not be read.
	lyingAnnotations := map[string]string{
		"dev.sigstore.bundle.predicateType": cosignSignPredicateType,
	}

	sigLayerDigest := digestOf(sigBundle)
	attLayerDigest := digestOf(attBundle)
	configDigest := digestOf(fakeConfig)

	sigManifestBytes, sigManifestDigest := buildManifest(
		bundleArtifactType, sigLayerDigest, len(sigBundle), configDigest, lyingAnnotations,
	)
	attManifestBytes, attManifestDigest := buildManifest(
		bundleArtifactType, attLayerDigest, len(attBundle), configDigest, lyingAnnotations,
	)

	hexDigest := strings.TrimPrefix(testImageDigest, "sha256:")
	repo := "/repo"

	routes := map[string]route{
		repo + "/referrers/sha256:" + hexDigest: {
			contentType: "application/vnd.oci.image.index.v1+json",
			body: buildTwoBundleReferrersIndex(
				sigManifestDigest, len(sigManifestBytes),
				attManifestDigest, len(attManifestBytes),
			),
		},
		repo + "/manifests/" + sigManifestDigest: {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        sigManifestBytes,
		},
		repo + "/manifests/" + attManifestDigest: {
			contentType: "application/vnd.oci.image.manifest.v1+json",
			body:        attManifestBytes,
		},
		repo + "/blobs/" + sigLayerDigest: {body: sigBundle},
		repo + "/blobs/" + attLayerDigest: {body: attBundle},
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

	is.True(result.SignaturePresent)   // the cosign/sign/v1 bundle
	is.True(result.AttestationPresent) // the SPDX bundle

	// The reported predicate comes from the attestation, not from the
	// signature's cosign/sign/v1 marker.
	is.Equal(result.PredicateType, "https://spdx.dev/Document")
}

// TestBundleIsSignature_RealFixtures pins the discriminator itself against both
// real bundles, independent of the discovery plumbing.
func TestBundleIsSignature_RealFixtures(t *testing.T) {
	is := is.New(t)

	sigBundle, err := os.ReadFile("testdata/bundle_sig_layer.json")
	is.NoErr(err)
	attBundle, err := os.ReadFile("testdata/bundle_att_layer.json")
	is.NoErr(err)

	is.True(bundleIsSignature(sigBundle))
	is.True(!bundleIsSignature(attBundle))
	is.True(!bundleIsSignature([]byte("not json")))
}

// TestExtractRekorFromBundle reads the log index out of a bundle signature's
// inline tlog entry. A bundle carries no dev.sigstore.cosign/bundle annotation,
// so without this the UI loses its Rekor link — and logIndex is a JSON *string*,
// because the bundle is protobuf-defined and protojson encodes int64 that way.
func TestExtractRekorFromBundle(t *testing.T) {
	is := is.New(t)

	sigBundle, err := os.ReadFile("testdata/bundle_sig_layer.json")
	is.NoErr(err)

	p := &Provenance{}
	extractFromSigLayer(p, signedLayer{ArtifactType: bundleArtifactType, Bytes: sigBundle})

	is.Equal(p.RekorLogIndex, int64(696618720))
	is.Equal(p.PredicateType, "") // cosign/sign/v1 is a marker, not a predicate
	is.Equal(len(p.Subjects), 0)
}

// ----- verification ----------------------------------------------------------

// testBundleStatement is an in-toto statement bound to testImageDigest, the
// payload a bundle DSSE envelope signs. verify.WithArtifactDigest checks the
// subject digest here, which is how a bundle gets bound to its image.
func testBundleStatement(digest string) []byte {
	return []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1",` +
		`"subject":[{"name":"example.com/repo","digest":{"sha256":"` + strings.TrimPrefix(digest, "sha256:") + `"}}],` +
		`"predicate":{"buildDefinition":{},"runDetails":{"builder":{"id":"https://example.com/builder"}}}}`)
}

// bundleJSONFromEntity assembles the new-format bundle JSON a cosign-signed
// image would carry from a VirtualSigstore-attested TestEntity — the bundle
// sibling of annotationsFromEntity.
//
// The SET is re-signed rather than read off the entity for the same reason
// annotationsFromEntity re-signs it: VirtualSigstore builds its tlog entry
// through the legacy tlog.NewEntry path, which keeps the SET on an unexported
// field and never populates TransparencyLogEntry.InclusionPromise. Verification
// needs it there, so it is regenerated over the same canonicalized payload.
func bundleJSONFromEntity(t *testing.T, virtualCA *ca.VirtualSigstore, entity *ca.TestEntity) []byte {
	t.Helper()
	is := is.New(t)

	vc, err := entity.VerificationContent()
	is.NoErr(err)

	sc, err := entity.SignatureContent()
	is.NoErr(err)
	env, ok := sc.(*sgbundle.Envelope)
	is.True(ok)

	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	is.NoErr(err)
	sigs := make([]*protodsse.Signature, 0, len(env.Signatures))
	for _, s := range env.Signatures {
		raw, decErr := base64.StdEncoding.DecodeString(s.Sig)
		is.NoErr(decErr)
		sigs = append(sigs, &protodsse.Signature{Sig: raw, Keyid: s.KeyID})
	}

	tlogEntries, err := entity.TlogEntries()
	is.NoErr(err)
	is.True(len(tlogEntries) > 0)

	entries := make([]*protorekor.TransparencyLogEntry, 0, len(tlogEntries))
	for _, e := range tlogEntries {
		tle, cloneOK := proto.Clone(e.TransparencyLogEntry()).(*protorekor.TransparencyLogEntry)
		is.True(cloneOK)
		set, signErr := virtualCA.RekorSignPayload(tlog.RekorPayload{
			Body:           base64.StdEncoding.EncodeToString(tle.GetCanonicalizedBody()),
			IntegratedTime: tle.GetIntegratedTime(),
			LogIndex:       tle.GetLogIndex(),
			LogID:          fmt.Sprintf("%x", tle.GetLogId().GetKeyId()),
		})
		is.NoErr(signErr)
		tle.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
		// tlog.NewEntry leaves KindVersion unset too, and ParseTransparencyLogEntry
		// rejects a bundle without it. Both values are in the canonicalized body.
		var body struct {
			Kind       string `json:"kind"`
			APIVersion string `json:"apiVersion"`
		}
		is.NoErr(json.Unmarshal(tle.GetCanonicalizedBody(), &body))
		tle.KindVersion = &protorekor.KindVersion{Kind: body.Kind, Version: body.APIVersion}
		entries = append(entries, tle)
	}

	pb := &protobundle.Bundle{
		MediaType: bundleArtifactType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: vc.Certificate().Raw},
			},
			TlogEntries: entries,
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     payload,
				PayloadType: env.PayloadType,
				Signatures:  sigs,
			},
		},
	}

	b, err := sgbundle.NewBundle(pb)
	is.NoErr(err)
	data, err := b.MarshalJSON()
	is.NoErr(err)
	return data
}

// bundleLayerFor produces the layer discovery would build for one bundle signed
// as testKeylessIdentity over a statement bound to subjectDigest.
func bundleLayerFor(t *testing.T, virtualCA *ca.VirtualSigstore, subjectDigest string) signedLayer {
	t.Helper()
	is := is.New(t)
	// generateInclusionProof: true — a v0.3 bundle is rejected at parse time
	// without one, and VirtualSigstore's plain Attest() produces only a promise.
	entity, err := virtualCA.AttestAtTime(testKeylessIdentity, testKeylessIssuer,
		testBundleStatement(subjectDigest), time.Now().Add(5*time.Minute), true)
	is.NoErr(err)
	return signedLayer{
		ArtifactType: bundleArtifactType,
		Bytes:        bundleJSONFromEntity(t, virtualCA, entity),
	}
}

func keylessCfg(identity string) trust.Config {
	return trust.Config{Mode: "keyless", Identity: "^" + identity + "$", Issuer: testKeylessIssuer}
}

func TestApplyKeylessVerification_BundleSignatureVerifies(t *testing.T) {
	is := is.New(t)
	virtualCA := newVirtualSigstore(t)
	useFixtureTrustedRoot(t, virtualCA)

	p := &Provenance{}
	raw := RawArtifacts{Sigs: []signedLayer{bundleLayerFor(t, virtualCA, testImageDigest)}}

	applyKeylessVerification(context.Background(), p, raw, keylessCfg(testKeylessIdentity), testImageDigest, true)

	is.True(p.Verified != nil)
	is.True(*p.Verified)
	is.Equal(p.SignerIssuer, testKeylessIssuer)
}

func TestApplyKeylessVerification_BundleWrongIdentityFails(t *testing.T) {
	is := is.New(t)
	virtualCA := newVirtualSigstore(t)
	useFixtureTrustedRoot(t, virtualCA)

	p := &Provenance{}
	raw := RawArtifacts{Sigs: []signedLayer{bundleLayerFor(t, virtualCA, testImageDigest)}}

	applyKeylessVerification(context.Background(), p, raw, keylessCfg(testUntrustedIdentity), testImageDigest, true)

	is.True(p.Verified != nil)
	is.True(!*p.Verified)
}

// TestApplyKeylessVerification_TransplantedBundleFails is the check that proves
// verify.WithArtifactDigest really replaced co.ClaimVerifier rather than quietly
// dropping the subject binding: the bundle is entirely valid, just signed over a
// statement naming a different image.
func TestApplyKeylessVerification_TransplantedBundleFails(t *testing.T) {
	is := is.New(t)
	virtualCA := newVirtualSigstore(t)
	useFixtureTrustedRoot(t, virtualCA)

	const otherDigest = "sha256:00000000000000000000000000000000000000000000000000000000deadbeef"

	p := &Provenance{}
	raw := RawArtifacts{Sigs: []signedLayer{bundleLayerFor(t, virtualCA, otherDigest)}}

	applyKeylessVerification(context.Background(), p, raw, keylessCfg(testKeylessIdentity), testImageDigest, true)

	is.True(p.Verified != nil)
	is.True(!*p.Verified)
}

func TestApplyKeylessVerification_BundleAttestationVerifies(t *testing.T) {
	is := is.New(t)
	virtualCA := newVirtualSigstore(t)
	useFixtureTrustedRoot(t, virtualCA)

	p := &Provenance{}
	raw := RawArtifacts{Atts: []signedLayer{bundleLayerFor(t, virtualCA, testImageDigest)}}

	applyKeylessVerification(context.Background(), p, raw, keylessCfg(testKeylessIdentity), testImageDigest, true)

	is.True(p.Verified != nil)
	is.True(*p.Verified)
}

// TestApplyKeylessVerification_MixedLegacyAndBundleSignatures guards the
// dispatch: an image may carry both an old annotation-based signature and a new
// bundle, and whichever is listed second must still be reachable.
func TestApplyKeylessVerification_MixedLegacyAndBundleSignatures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		bundleFirst bool
	}{
		{"bundle first", true},
		{"legacy first", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			virtualCA := newVirtualSigstore(t)
			useFixtureTrustedRoot(t, virtualCA)

			// Only the bundle carries the trusted identity, so success proves the
			// bundle branch ran rather than the legacy one happening to pass.
			legacy := signedLayerFor(t, virtualCA, testUntrustedIdentity)
			bundle := bundleLayerFor(t, virtualCA, testImageDigest)

			sigs := []signedLayer{legacy, bundle}
			if tc.bundleFirst {
				sigs = []signedLayer{bundle, legacy}
			}

			p := &Provenance{}
			applyKeylessVerification(context.Background(), p,
				RawArtifacts{Sigs: sigs}, keylessCfg(testKeylessIdentity), testImageDigest, true)

			is.True(p.Verified != nil)
			is.True(*p.Verified)
		})
	}
}
