package provenance

import (
	"context"
	"crypto"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/pfenerty/ocidex/internal/trust"
)

// applyVerification sets p.Verified based on the registry trust configuration.
// mode "public_key" with a non-empty pemKey triggers verification of both the
// simplesigning sig and the DSSE attestation against that key, via the same
// cosign.CheckOpts pipeline the keyless path uses (see keyless.go) — here
// co.SigVerifier carries the trust source instead of co.TrustedMaterial.
// IgnoreTlog is set because a public-key signature carries no Rekor bundle to
// check offline; that's a semantic difference from the keyless path, not an
// oversight.
//
// Verification requires not only a valid signature against the trusted key but
// also that the signed payload is bound to imageDigest (the artifact being
// enriched) — enforced by cosign's SimpleClaimVerifier / IntotoSubjectClaimVerifier —
// preventing a valid signature from being transplanted from a different image
// signed by the same key.
func applyVerification(ctx context.Context, p *Provenance, raw RawArtifacts, mode, pemKey, imageDigest string) {
	if mode != trust.ModePublicKey || pemKey == "" {
		return
	}
	if !raw.SigPresent && !raw.AttPresent {
		return
	}
	pubkey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pemKey))
	if err != nil {
		return
	}
	verifier, err := signature.LoadVerifier(pubkey, crypto.SHA256)
	if err != nil {
		return
	}
	h, err := v1.NewHash(imageDigest)
	if err != nil {
		return
	}

	co := cosign.CheckOpts{
		SigVerifier: verifier,
		IgnoreTlog:  true,
		IgnoreSCT:   true,
	}

	checked := false
	verified := true
	if raw.SigPresent {
		checked = true
		verified = verified && verifyOCISignature(ctx, raw, h, co)
	}
	if raw.AttPresent && raw.AttArtifactType != inTotoArtifactType {
		// Raw in-toto atts (buildkit-native) carry no envelope signature and are
		// excluded from cryptographic verification, matching applyKeylessVerification.
		checked = true
		verified = verified && verifyOCIAttestation(ctx, raw, h, co)
	}
	if !checked {
		// Only raw in-toto attestations are present (no cosign signature, no
		// non-in-toto attestation) — nothing was actually verified. Leave
		// p.Verified nil so SigningStatus falls through to "signed" rather
		// than falsely reporting "verified".
		return
	}
	p.Verified = &verified
}
