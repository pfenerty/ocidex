package provenance

import (
	"context"
	"crypto"
	"strings"
	"unicode/utf8"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/pfenerty/ocidex/internal/trust"
)

// applyVerification sets p.Verified — and, when verification does not succeed,
// p.VerificationError — based on the registry trust configuration.
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
	if !raw.SigPresent() && !raw.AttPresent() {
		return
	}
	// A failure below means verification could not run at all, as opposed to
	// running and rejecting. p.Verified stays nil (SigningStatus keeps reading
	// "signed"), but the reason is recorded so a misconfigured trust key is
	// visible in the UI instead of only in this worker's logs (ocidex-j9qa).
	pubkey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pemKey))
	if err != nil {
		setVerificationError(p, "trust public key: "+err.Error())
		return
	}
	verifier, err := signature.LoadVerifier(pubkey, crypto.SHA256)
	if err != nil {
		setVerificationError(p, "trust public key: "+err.Error())
		return
	}
	h, err := v1.NewHash(imageDigest)
	if err != nil {
		setVerificationError(p, "image digest: "+err.Error())
		return
	}

	co := cosign.CheckOpts{
		SigVerifier: verifier,
		IgnoreTlog:  true,
		IgnoreSCT:   true,
	}

	verifyAgainst(ctx, p, raw, h, co)
}

// maxVerificationErrorLen bounds VerificationError. cosign errors can embed a
// full certificate subject list, and the value is stored per SBOM in the
// enrichment JSONB and rendered in the UI, so it is capped rather than left
// registry-controlled and unbounded.
const maxVerificationErrorLen = 500

// setVerificationError stores reason on p, flattened to one line (errors.Join
// separates with newlines, and individual cosign errors are sometimes multi-line
// themselves) and truncated to maxVerificationErrorLen. The cut is made on a
// rune boundary: a signer identity can be non-ASCII, and slicing mid-sequence
// would leave a replacement character in the stored JSON.
func setVerificationError(p *Provenance, reason string) {
	parts := make([]string, 0, 4)
	for _, line := range strings.Split(reason, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			parts = append(parts, line)
		}
	}
	reason = strings.Join(parts, "; ")
	if reason == "" {
		return
	}
	if len(reason) > maxVerificationErrorLen {
		cut := maxVerificationErrorLen
		for cut > 0 && !utf8.RuneStart(reason[cut]) {
			cut--
		}
		reason = reason[:cut] + "\u2026"
	}
	p.VerificationError = reason
}

// verifyAgainst runs signature and attestation verification for raw against co,
// stamping p.Verified and p.VerificationError. It reports whether anything was
// actually checked — false means only raw in-toto attestations were present
// (nothing to verify), and p is left untouched so SigningStatus falls through to
// "signed" rather than falsely reporting "verified".
//
// Shared by the public-key path above and applyKeylessVerification in keyless.go;
// the two differ only in how co carries the trust source and in what the keyless
// path stamps on success.
func verifyAgainst(ctx context.Context, p *Provenance, raw RawArtifacts, h v1.Hash, co cosign.CheckOpts) bool {
	checked := false
	verified := true
	var reasons []string

	if raw.SigPresent() {
		checked = true
		if idx, err := verifyOCISignatures(ctx, raw.Sigs, h, co); idx >= 0 {
			restampFromSig(p, raw.Sigs[idx])
		} else {
			verified = false
			reasons = append(reasons, "signature: "+errText(err))
		}
	}
	if atts := raw.verifiableAtts(); len(atts) > 0 {
		// Raw in-toto atts (buildkit-native) carry no envelope signature and are
		// excluded from cryptographic verification.
		checked = true
		if idx, err := verifyOCIAttestations(ctx, atts, h, co); idx < 0 {
			verified = false
			reasons = append(reasons, "attestation: "+errText(err))
		}
	}
	if !checked {
		return false
	}

	p.Verified = &verified
	if !verified {
		setVerificationError(p, strings.Join(reasons, "; "))
	}
	return true
}

// errText renders err for VerificationError, tolerating a nil error so the
// reason never reads as an empty string.
func errText(err error) string {
	if err == nil {
		return "rejected"
	}
	return err.Error()
}
