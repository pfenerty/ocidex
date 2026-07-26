package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/empty"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// trustedRootCacheTTL controls how often the Sigstore public-good trusted root
// (Fulcio CAs, Rekor/CT log public keys) is re-fetched via TUF.
const trustedRootCacheTTL = 24 * time.Hour

var (
	trustedRootMu        sync.Mutex
	trustedRootCache     *root.TrustedRoot
	trustedRootFetchedAt time.Time
)

// trustedMaterialProvider resolves the trust material used for Fulcio/Rekor
// verification. Overridable in tests to avoid a live TUF fetch.
var trustedMaterialProvider = func() (root.TrustedMaterial, error) { return getTrustedRoot() }

// testIgnoreSCT disables the requirement that the Fulcio cert carry an
// embedded Signed Certificate Timestamp. Production must never set this true:
// real Fulcio-issued certs always embed an SCT, and skipping the check would
// accept a cert Fulcio never actually vouched for via the CT log. It exists
// solely so tests using ca.VirtualSigstore (github.com/sigstore/sigstore-go's
// own in-memory test CA, which stubs CTLogs() to satisfy the TrustedMaterial
// interface but never embeds SCTs into the certs it issues) can exercise the
// rest of the verification pipeline.
var testIgnoreSCT bool

// getTrustedRoot returns the cached Sigstore public-good trusted root, fetching
// (or refreshing) it via TUF when the cache is empty or stale.
func getTrustedRoot() (*root.TrustedRoot, error) {
	trustedRootMu.Lock()
	defer trustedRootMu.Unlock()
	if trustedRootCache != nil && time.Since(trustedRootFetchedAt) < trustedRootCacheTTL {
		return trustedRootCache, nil
	}
	tr, err := root.FetchTrustedRoot()
	if err != nil {
		if trustedRootCache != nil {
			// Serve the stale root rather than failing every verification because
			// of a transient TUF fetch error.
			return trustedRootCache, nil
		}
		return nil, fmt.Errorf("fetching sigstore trusted root: %w", err)
	}
	trustedRootCache = tr
	trustedRootFetchedAt = time.Now()
	return tr, nil
}

// applyKeylessVerification sets p.Verified based on Fulcio certificate chain +
// Rekor transparency log verification. Discovery already happened (raw is the
// same RawArtifacts our own OCI fetch produced); cryptographic verification is
// delegated to cosign's own verify pipeline (github.com/sigstore/cosign/v2) —
// the reference implementation for exactly this check — by wrapping the
// already-fetched signature/attestation bytes and annotations into an
// oci.Signature via the static package, rather than re-fetching from the
// registry or hand-parsing the Sigstore bundle format ourselves.
//
// Verification is offline (Offline: true): cosign verifies the Rekor
// inclusion promise (SET) embedded in its own OCI bundle annotation against
// trustedMaterial's Rekor public key, with no live call to rekor.sigstore.dev.
func applyKeylessVerification(ctx context.Context, p *Provenance, raw RawArtifacts, cfg TrustConfig, imageDigest string) {
	if cfg.Identity == "" || cfg.Issuer == "" {
		return
	}
	if !raw.SigPresent && !raw.AttPresent {
		return
	}

	trustedMaterial, err := trustedMaterialProvider()
	if err != nil {
		slog.ErrorContext(ctx, "keyless verification: fetching trusted root", "err", err)
		return
	}
	h, err := v1.NewHash(imageDigest)
	if err != nil {
		slog.ErrorContext(ctx, "keyless verification: parsing image digest", "err", err)
		return
	}

	baseOpts := cosign.CheckOpts{
		TrustedMaterial: trustedMaterial,
		Identities:      []cosign.Identity{{SubjectRegExp: cfg.Identity, Issuer: cfg.Issuer}},
		Offline:         true,
		IgnoreSCT:       testIgnoreSCT,
	}

	verified := true
	if raw.SigPresent {
		verified = verified && verifyOCISignature(ctx, raw, h, baseOpts)
	}
	if raw.AttPresent && raw.AttArtifactType != inTotoArtifactType {
		// Raw in-toto atts (buildkit-native) carry no envelope signature and are
		// excluded from cryptographic verification, matching applyVerification.
		verified = verified && verifyOCIAttestation(ctx, raw, h, baseOpts)
	}
	p.Verified = &verified
	if verified {
		p.SignerIdentity = cfg.Identity
		p.SignerIssuer = cfg.Issuer
	}
}

// verifyOCISignature verifies the cosign simplesigning signature (the
// OCI-attached image signature) against co, using SimpleClaimVerifier to bind
// the payload to h (rejecting a valid signature transplanted from a different
// image). Shared by both the keyless (Fulcio+Rekor via co.TrustedMaterial)
// and public-key (co.SigVerifier) verification paths — co determines which
// trust source is actually checked.
func verifyOCISignature(ctx context.Context, raw RawArtifacts, h v1.Hash, co cosign.CheckOpts) bool {
	sig, err := buildOCISignature(raw.SigLayerBytes, raw.SigAnnotations)
	if err != nil {
		return false
	}
	co.ClaimVerifier = cosign.SimpleClaimVerifier
	_, err = cosign.VerifyImageSignature(ctx, sig, h, &co)
	return err == nil
}

// verifyOCIAttestation verifies a DSSE-enveloped SLSA attestation against co,
// using IntotoSubjectClaimVerifier to require the envelope's in-toto subject
// to bind to h. Shared by both the keyless and public-key verification paths
// (see verifyOCISignature).
func verifyOCIAttestation(ctx context.Context, raw RawArtifacts, h v1.Hash, co cosign.CheckOpts) bool {
	att, err := static.NewAttestation(raw.AttLayerBytes, buildStaticOptions(raw.AttAnnotations)...)
	if err != nil {
		return false
	}
	atts, err := mutate.AppendSignatures(empty.Signatures(), false, att)
	if err != nil {
		return false
	}
	co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	_, _, err = cosign.VerifyImageAttestation(ctx, atts, h, &co)
	return err == nil
}

// buildOCISignature wraps an already-fetched simplesigning payload and its
// annotations into an oci.Signature cosign's verify functions can consume.
func buildOCISignature(payload []byte, annotations map[string]string) (oci.Signature, error) {
	b64sig := annotations["dev.cosignproject.cosign/signature"]
	if b64sig == "" {
		return nil, fmt.Errorf("missing signature annotation")
	}
	return static.NewSignature(payload, b64sig, buildStaticOptions(annotations)...)
}

// buildStaticOptions extracts the certificate chain and Rekor bundle (if
// present) from cosign's OCI annotations into static.Options. The bundle
// annotation is cosign's own JSON encoding of a cbundle.RekorBundle
// (github.com/sigstore/cosign/v2/pkg/oci/static WithBundle marshals it
// directly), so round-tripping it back through json.Unmarshal reconstructs
// exactly what cosign's verify path expects — no hand-parsing required.
func buildStaticOptions(annotations map[string]string) []static.Option {
	var opts []static.Option
	if certPEM := annotations["dev.sigstore.cosign/certificate"]; certPEM != "" {
		chainPEM := annotations["dev.sigstore.cosign/chain"]
		opts = append(opts, static.WithCertChain([]byte(certPEM), []byte(chainPEM)))
	}
	if bundleJSON := annotations["dev.sigstore.cosign/bundle"]; bundleJSON != "" {
		var b cbundle.RekorBundle
		if err := json.Unmarshal([]byte(bundleJSON), &b); err == nil {
			opts = append(opts, static.WithBundle(&b))
		}
	}
	return opts
}
