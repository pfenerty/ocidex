package provenance

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/matryer/is"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// ----- buildTlogEntry ---------------------------------------------------------

func TestBuildTlogEntry_Valid(t *testing.T) {
	is := is.New(t)
	bundleJSON := `{"SignedEntryTimestamp":"` + base64.StdEncoding.EncodeToString([]byte("fake-set")) + `","Payload":{"body":"` +
		base64.StdEncoding.EncodeToString([]byte(`{"kind":"hashedrekord"}`)) +
		`","integratedTime":1700000000,"logIndex":12345,"logID":"` + strings.Repeat("ab", 32) + `"}}`

	entry, err := buildTlogEntry(bundleJSON, "hashedrekord")

	is.NoErr(err)
	is.Equal(entry.LogIndex, int64(12345))
	is.Equal(entry.IntegratedTime, int64(1700000000))
	is.Equal(entry.KindVersion.Kind, "hashedrekord")
	is.Equal(string(entry.CanonicalizedBody), `{"kind":"hashedrekord"}`)
	is.Equal(string(entry.InclusionPromise.SignedEntryTimestamp), "fake-set")
	is.Equal(len(entry.LogId.KeyId), 32) // sha256 logID, hex-decoded
}

func TestBuildTlogEntry_Empty(t *testing.T) {
	is := is.New(t)
	_, err := buildTlogEntry("", "hashedrekord")
	is.True(err != nil)
}

func TestBuildTlogEntry_MissingFields(t *testing.T) {
	is := is.New(t)
	// No SignedEntryTimestamp, no body: cosign always sets these together, so
	// treat a partial bundle as unusable rather than guessing.
	_, err := buildTlogEntry(`{"Payload":{"logIndex":1,"logID":"aa"}}`, "hashedrekord")
	is.True(err != nil)
}

func TestBuildTlogEntry_InvalidJSON(t *testing.T) {
	is := is.New(t)
	_, err := buildTlogEntry("not json", "hashedrekord")
	is.True(err != nil)
}

// ----- buildCertificateIdentity ------------------------------------------------

func TestBuildCertificateIdentity_Valid(t *testing.T) {
	is := is.New(t)
	_, err := buildCertificateIdentity(TrustConfig{
		Mode:     "keyless",
		Identity: "^https://github.com/example/repo/.*$",
		Issuer:   "https://token.actions.githubusercontent.com",
	})
	is.NoErr(err)
}

func TestBuildCertificateIdentity_BadRegex(t *testing.T) {
	is := is.New(t)
	_, err := buildCertificateIdentity(TrustConfig{
		Mode:     "keyless",
		Identity: "(unclosed",
		Issuer:   "https://token.actions.githubusercontent.com",
	})
	is.True(err != nil)
}

// ----- applyKeylessVerification: guard clauses ---------------------------------

func TestApplyKeylessVerification_NoOpWithoutIdentityOrIssuer(t *testing.T) {
	is := is.New(t)
	p := &Provenance{}
	raw := RawArtifacts{SigPresent: true}

	applyKeylessVerification(context.Background(), p, raw, TrustConfig{Mode: "keyless"}, testImageDigest)

	is.True(p.Verified == nil) // no identity/issuer configured: verification not attempted
}

func TestApplyKeylessVerification_NoOpWithoutSignatureOrAttestation(t *testing.T) {
	is := is.New(t)
	p := &Provenance{}
	raw := RawArtifacts{} // SigPresent=false, AttPresent=false
	cfg := TrustConfig{Mode: "keyless", Identity: "^foo$", Issuer: "https://issuer.example"}

	applyKeylessVerification(context.Background(), p, raw, cfg, testImageDigest)

	is.True(p.Verified == nil)
}

func TestApplyKeylessVerification_FailsClosedOnTrustedRootError(t *testing.T) {
	is := is.New(t)
	orig := trustedMaterialProvider
	trustedMaterialProvider = func() (root.TrustedMaterial, error) {
		return nil, errors.New("simulated TUF fetch failure")
	}
	defer func() { trustedMaterialProvider = orig }()

	p := &Provenance{}
	raw := RawArtifacts{SigPresent: true, SigAnnotations: map[string]string{
		"dev.cosignproject.cosign/signature": "not-a-real-signature",
	}}
	cfg := TrustConfig{Mode: "keyless", Identity: "^foo$", Issuer: "https://issuer.example"}

	applyKeylessVerification(context.Background(), p, raw, cfg, testImageDigest)

	// Infrastructure failure (can't fetch trust material) leaves Verified unset
	// rather than reporting a false verification failure, matching the
	// public-key path's contract when a required input is unavailable.
	is.True(p.Verified == nil)
}

// ----- verifyKeylessMessageSignature: malformed input fails closed -------------

func TestVerifyKeylessMessageSignature_MissingCertificate(t *testing.T) {
	is := is.New(t)
	raw := RawArtifacts{
		SigAnnotations: map[string]string{
			"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString([]byte("sig")),
		},
		SigLayerBytes: fakeSigPayload,
	}
	certID, err := buildCertificateIdentity(TrustConfig{Identity: "^foo$", Issuer: "https://issuer.example"})
	is.NoErr(err)

	ok := verifyKeylessMessageSignature(nil, certID, raw, testImageDigest)

	is.True(!ok) // no certificate annotation present: must not verify
}

func TestVerifyKeylessMessageSignature_DigestMismatch(t *testing.T) {
	is := is.New(t)
	raw := RawArtifacts{
		SigAnnotations: map[string]string{
			"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString([]byte("sig")),
			"dev.sigstore.cosign/certificate":    "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n",
		},
		SigLayerBytes: fakeSigPayload, // bound to testImageDigest
	}
	certID, err := buildCertificateIdentity(TrustConfig{Identity: "^foo$", Issuer: "https://issuer.example"})
	is.NoErr(err)

	ok := verifyKeylessMessageSignature(nil, certID, raw, "sha256:deadbeef")

	is.True(!ok) // signature is bound to a different digest than the one being verified
}
