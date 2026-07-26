package provenance

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	"github.com/matryer/is"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"

	"github.com/pfenerty/ocidex/internal/trust"
)

// ----- fixture: a real, cryptographically valid keyless signature ------------
//
// ca.VirtualSigstore (github.com/sigstore/sigstore-go/pkg/testing/ca) is an
// in-memory Fulcio CA + Rekor log used by sigstore-go's own test suite. It
// produces a genuine leaf cert (with SAN/issuer extensions), signature, and
// Rekor tlog entry — letting us exercise the real cosign verify pipeline
// end-to-end (cert chain validation, offline SET verification, identity
// matching) without a live network call or a hand-built fixture.

const (
	testKeylessIdentity = "https://github.com/example/repo/.github/workflows/release.yml@refs/tags/v1.0.0"
	testKeylessIssuer   = "https://token.actions.githubusercontent.com"
)

func newVirtualSigstore(t *testing.T) *ca.VirtualSigstore {
	t.Helper()
	is := is.New(t)
	virtualCA, err := ca.NewVirtualSigstore()
	is.NoErr(err)
	return virtualCA
}

// annotationsFromEntity builds the OCI annotations a real cosign-signed image
// would carry from a VirtualSigstore-signed TestEntity: certificate, chain,
// base64 signature, and the dev.sigstore.cosign/bundle JSON (SET + canonical
// body + logID/logIndex/integratedTime) that lets verification stay offline.
//
// tlog.Entry.TransparencyLogEntry() doesn't surface the SET produced by the
// legacy tlog.NewEntry construction path VirtualSigstore uses internally (it's
// only kept on an unexported field) — so rather than extract it, we ask
// VirtualSigstore's exported RekorSignPayload for a fresh signature over the
// same canonicalized payload. ECDSA signing isn't deterministic, but any valid
// signature over the correct payload verifies identically.
func annotationsFromEntity(t *testing.T, virtualCA *ca.VirtualSigstore, entity *ca.TestEntity) map[string]string {
	t.Helper()
	is := is.New(t)

	vc, err := entity.VerificationContent()
	is.NoErr(err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: vc.Certificate().Raw})
	var chainPEM []byte //nolint:prealloc // final size depends on variable-length PEM encoding per cert
	for _, c := range vc.Intermediates() {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}

	sc, err := entity.SignatureContent()
	is.NoErr(err)

	tlogEntries, err := entity.TlogEntries()
	is.NoErr(err)
	is.True(len(tlogEntries) > 0)
	pbEntry := tlogEntries[0].TransparencyLogEntry()

	bodyB64 := base64.StdEncoding.EncodeToString(pbEntry.GetCanonicalizedBody())
	logIDHex := hex.EncodeToString(pbEntry.GetLogId().GetKeyId())
	set, err := virtualCA.RekorSignPayload(tlog.RekorPayload{
		Body:           bodyB64,
		IntegratedTime: pbEntry.GetIntegratedTime(),
		LogIndex:       pbEntry.GetLogIndex(),
		LogID:          logIDHex,
	})
	is.NoErr(err)

	bundleJSON := fmt.Sprintf(
		`{"SignedEntryTimestamp":%q,"Payload":{"body":%q,"integratedTime":%d,"logIndex":%d,"logID":%q}}`,
		base64.StdEncoding.EncodeToString(set),
		bodyB64,
		pbEntry.GetIntegratedTime(),
		pbEntry.GetLogIndex(),
		logIDHex,
	)

	return map[string]string{
		"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(sc.Signature()),
		"dev.sigstore.cosign/certificate":    string(certPEM),
		"dev.sigstore.cosign/chain":          string(chainPEM),
		"dev.sigstore.cosign/bundle":         bundleJSON,
	}
}

// useFixtureTrustedRoot points trustedMaterialProvider at the VirtualSigstore's
// own trust material (it implements root.TrustedMaterial directly) instead of
// doing a live TUF fetch, and disables the embedded-SCT requirement (see
// testIgnoreSCT's doc comment: VirtualSigstore never embeds one). Both are
// restored on test cleanup.
func useFixtureTrustedRoot(t *testing.T, virtualCA root.TrustedMaterial) {
	t.Helper()
	origMaterial := trustedMaterialProvider
	origIgnoreSCT := testIgnoreSCT
	trustedMaterialProvider = func() (root.TrustedMaterial, error) { return virtualCA, nil }
	testIgnoreSCT = true
	t.Cleanup(func() {
		trustedMaterialProvider = origMaterial
		testIgnoreSCT = origIgnoreSCT
	})
}

func TestApplyKeylessVerification_ValidSignatureVerifies(t *testing.T) {
	is := is.New(t)
	virtualCA := newVirtualSigstore(t)

	// Sign the simplesigning payload directly (what cosign actually signs for
	// an OCI image signature); fakeSigPayload is already bound to testImageDigest.
	entity, err := virtualCA.Sign(testKeylessIdentity, testKeylessIssuer, fakeSigPayload)
	is.NoErr(err)
	annotations := annotationsFromEntity(t, virtualCA, entity)
	useFixtureTrustedRoot(t, virtualCA)

	p := &Provenance{}
	raw := RawArtifacts{SigPresent: true, SigAnnotations: annotations, SigLayerBytes: fakeSigPayload}
	cfg := trust.Config{Mode: "keyless", Identity: "^" + testKeylessIdentity + "$", Issuer: testKeylessIssuer}

	applyKeylessVerification(context.Background(), p, raw, cfg, testImageDigest)

	is.True(p.Verified != nil)
	is.True(*p.Verified) // real Fulcio cert + Rekor bundle, matching identity/issuer: must verify
	is.Equal(p.SignerIssuer, testKeylessIssuer)
}

func TestApplyKeylessVerification_WrongIdentityFails(t *testing.T) {
	is := is.New(t)
	virtualCA := newVirtualSigstore(t)

	entity, err := virtualCA.Sign(testKeylessIdentity, testKeylessIssuer, fakeSigPayload)
	is.NoErr(err)
	annotations := annotationsFromEntity(t, virtualCA, entity)
	useFixtureTrustedRoot(t, virtualCA)

	p := &Provenance{}
	raw := RawArtifacts{SigPresent: true, SigAnnotations: annotations, SigLayerBytes: fakeSigPayload}
	// Configured to require a *different* identity than the one actually signed.
	cfg := trust.Config{Mode: "keyless", Identity: "^https://github.com/someone-else/other-repo/.*$", Issuer: testKeylessIssuer}

	applyKeylessVerification(context.Background(), p, raw, cfg, testImageDigest)

	is.True(p.Verified != nil)
	is.True(!*p.Verified)
}

func TestApplyKeylessVerification_TransplantedSignatureFails(t *testing.T) {
	is := is.New(t)
	virtualCA := newVirtualSigstore(t)

	// Sign a payload bound to a *different* image digest than the one we then
	// ask to verify — the signature and cert are perfectly valid, just for the
	// wrong artifact. Must be rejected (this is the anti-transplant check
	// SimpleClaimVerifier performs on the payload's docker-manifest-digest).
	otherDigestPayload := []byte(`{"critical":{"identity":{"docker-reference":"example.com/repo"},"image":{"docker-manifest-digest":"sha256:dead000000000000000000000000000000000000000000000000000000beef"},"type":"cosign container image signature"},"optional":null}`)
	entity, err := virtualCA.Sign(testKeylessIdentity, testKeylessIssuer, otherDigestPayload)
	is.NoErr(err)
	annotations := annotationsFromEntity(t, virtualCA, entity)
	useFixtureTrustedRoot(t, virtualCA)

	p := &Provenance{}
	raw := RawArtifacts{SigPresent: true, SigAnnotations: annotations, SigLayerBytes: otherDigestPayload}
	cfg := trust.Config{Mode: "keyless", Identity: "^" + testKeylessIdentity + "$", Issuer: testKeylessIssuer}

	applyKeylessVerification(context.Background(), p, raw, cfg, testImageDigest)

	is.True(p.Verified != nil)
	is.True(!*p.Verified)
}

// ----- applyKeylessVerification: guard clauses ---------------------------------

func TestApplyKeylessVerification_NoOpWithoutIdentityOrIssuer(t *testing.T) {
	is := is.New(t)
	p := &Provenance{}
	raw := RawArtifacts{SigPresent: true}

	applyKeylessVerification(context.Background(), p, raw, trust.Config{Mode: "keyless"}, testImageDigest)

	is.True(p.Verified == nil) // no identity/issuer configured: verification not attempted
}

func TestApplyKeylessVerification_RawInTotoOnlyNoSignature(t *testing.T) {
	// goh.1: a raw in-toto attestation (buildkit-native) with no cosign
	// signature must not be reported as verified, and must not name a signer
	// whose certificate was never checked.
	is := is.New(t)
	p := &Provenance{}
	raw := RawArtifacts{SigPresent: false, AttPresent: true, AttArtifactType: inTotoArtifactType}
	cfg := trust.Config{Mode: "keyless", Identity: "^foo$", Issuer: "https://issuer.example"}

	applyKeylessVerification(context.Background(), p, raw, cfg, testImageDigest)

	is.True(p.Verified == nil)
	is.Equal(p.SignerIdentity, "")
	is.Equal(p.SignerIssuer, "")
}

func TestApplyKeylessVerification_NoOpWithoutSignatureOrAttestation(t *testing.T) {
	is := is.New(t)
	p := &Provenance{}
	raw := RawArtifacts{} // SigPresent=false, AttPresent=false
	cfg := trust.Config{Mode: "keyless", Identity: "^foo$", Issuer: "https://issuer.example"}

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
	raw := RawArtifacts{SigPresent: true}
	cfg := trust.Config{Mode: "keyless", Identity: "^foo$", Issuer: "https://issuer.example"}

	applyKeylessVerification(context.Background(), p, raw, cfg, testImageDigest)

	// Infrastructure failure (can't fetch trust material) leaves Verified unset
	// rather than reporting a false verification failure, matching the
	// public-key path's contract when a required input is unavailable.
	is.True(p.Verified == nil)
}
