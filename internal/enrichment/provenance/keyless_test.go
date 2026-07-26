package provenance

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/matryer/is"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// testDigestRef uses the RFC 2606 reserved .invalid TLD, guaranteed to never
// resolve, so tests never depend on real network reachability.
var testDigestRef = func() name.Digest {
	ref, err := name.NewDigest("registry.invalid/repo@" + testImageDigest)
	if err != nil {
		panic(err)
	}
	return ref
}()

// ----- applyKeylessVerification: guard clauses ---------------------------------

func TestApplyKeylessVerification_NoOpWithoutIdentityOrIssuer(t *testing.T) {
	is := is.New(t)
	p := &Provenance{}
	raw := RawArtifacts{SigPresent: true}

	applyKeylessVerification(context.Background(), p, raw, TrustConfig{Mode: "keyless"}, testDigestRef, nil)

	is.True(p.Verified == nil) // no identity/issuer configured: verification not attempted
}

func TestApplyKeylessVerification_NoOpWithoutSignatureOrAttestation(t *testing.T) {
	is := is.New(t)
	p := &Provenance{}
	raw := RawArtifacts{} // SigPresent=false, AttPresent=false
	cfg := TrustConfig{Mode: "keyless", Identity: "^foo$", Issuer: "https://issuer.example"}

	applyKeylessVerification(context.Background(), p, raw, cfg, testDigestRef, nil)

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
	raw := RawArtifacts{SigPresent: true}
	cfg := TrustConfig{Mode: "keyless", Identity: "^foo$", Issuer: "https://issuer.example"}

	applyKeylessVerification(context.Background(), p, raw, cfg, testDigestRef, nil)

	// Infrastructure failure (can't fetch trust material) leaves Verified unset
	// rather than reporting a false verification failure, matching the
	// public-key path's contract when a required input is unavailable.
	is.True(p.Verified == nil)
}

func TestApplyKeylessVerification_FailsClosedWhenCosignCannotVerify(t *testing.T) {
	is := is.New(t)
	orig := trustedMaterialProvider
	trustedMaterialProvider = func() (root.TrustedMaterial, error) {
		// A real (but useless for this unreachable/unsigned test ref) trusted
		// root, so we exercise the actual cosign.VerifyImageSignatures call
		// rather than short-circuiting on the trust-root fetch.
		return &root.TrustedRoot{}, nil
	}
	defer func() { trustedMaterialProvider = orig }()

	p := &Provenance{}
	raw := RawArtifacts{SigPresent: true}
	cfg := TrustConfig{Mode: "keyless", Identity: "^foo$", Issuer: "https://issuer.example"}

	// testDigestRef points at a registry that doesn't exist; cosign's own
	// fetch will fail, which must surface as Verified=false, not a crash or
	// a silently-skipped (nil) result.
	applyKeylessVerification(context.Background(), p, raw, cfg, testDigestRef, nil)

	is.True(p.Verified != nil)
	is.True(!*p.Verified)
}
