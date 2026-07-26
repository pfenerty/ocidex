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
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"golang.org/x/sync/singleflight"

	"github.com/pfenerty/ocidex/internal/trust"
)

// trustedRootCacheTTL controls how often the Sigstore public-good trusted root
// (Fulcio CAs, Rekor/CT log public keys) is re-fetched via TUF.
const trustedRootCacheTTL = 24 * time.Hour

// trustedRootFetchTimeout bounds a single TUF fetch attempt.
const trustedRootFetchTimeout = 30 * time.Second

// trustedRootMaxStaleness is the hard ceiling on how long a cached trusted
// root may keep being served while TUF fetches fail. Beyond this, a revoked
// Fulcio CA could plausibly have propagated, so verification must fail
// closed rather than trust stale material forever.
const trustedRootMaxStaleness = 7 * trustedRootCacheTTL

var (
	trustedRootMu        sync.Mutex
	trustedRootCache     *root.TrustedRoot
	trustedRootFetchedAt time.Time
	trustedRootGroup     singleflight.Group
)

// fetchTrustedRootFn performs the actual TUF fetch. Overridable in tests to
// avoid a live network call and to simulate concurrency/failure/timeout
// behavior.
var fetchTrustedRootFn = func(ctx context.Context) (*root.TrustedRoot, error) {
	return root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithContext(ctx))
}

// trustedMaterialProvider resolves the trust material used for Fulcio/Rekor
// verification. Overridable in tests to avoid a live TUF fetch.
var trustedMaterialProvider = func(ctx context.Context) (root.TrustedMaterial, error) {
	return getTrustedRoot(ctx)
}

// getTrustedRoot returns the cached Sigstore public-good trusted root, fetching
// (or refreshing) it via TUF when the cache is empty or stale. Concurrent
// callers that all observe a stale/empty cache collapse into a single
// in-flight fetch (singleflight) rather than serializing behind a lock held
// for the whole network round trip.
func getTrustedRoot(ctx context.Context) (*root.TrustedRoot, error) {
	if tr, ok := freshCachedTrustedRoot(); ok {
		return tr, nil
	}

	v, err, _ := trustedRootGroup.Do("trusted-root", func() (any, error) {
		// Another goroutine may have refreshed the cache while this one was
		// waiting to enter Do.
		if tr, ok := freshCachedTrustedRoot(); ok {
			return tr, nil
		}

		fetchCtx, cancel := context.WithTimeout(ctx, trustedRootFetchTimeout)
		defer cancel()
		tr, err := fetchTrustedRootFn(fetchCtx)
		if err != nil {
			trustedRootMu.Lock()
			cached, fetchedAt := trustedRootCache, trustedRootFetchedAt
			trustedRootMu.Unlock()
			if cached != nil && time.Since(fetchedAt) < trustedRootMaxStaleness {
				// Serve the stale root rather than failing every verification
				// because of a transient TUF fetch error, but only up to
				// trustedRootMaxStaleness — beyond that a revoked Fulcio CA
				// could plausibly have propagated, so fail closed instead.
				slog.WarnContext(ctx, "keyless verification: serving stale trusted root after TUF fetch failure",
					"err", err, "age", time.Since(fetchedAt))
				return cached, nil
			}
			return nil, fmt.Errorf("fetching sigstore trusted root: %w", err)
		}

		trustedRootMu.Lock()
		trustedRootCache = tr
		trustedRootFetchedAt = time.Now()
		trustedRootMu.Unlock()
		return tr, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*root.TrustedRoot), nil
}

// freshCachedTrustedRoot returns the cached trusted root if it is within
// trustedRootCacheTTL.
func freshCachedTrustedRoot() (*root.TrustedRoot, bool) {
	trustedRootMu.Lock()
	defer trustedRootMu.Unlock()
	if trustedRootCache != nil && time.Since(trustedRootFetchedAt) < trustedRootCacheTTL {
		return trustedRootCache, true
	}
	return nil, false
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
//
// ignoreSCT disables the requirement that the Fulcio cert carry an embedded
// Signed Certificate Timestamp. Production always passes false: real
// Fulcio-issued certs always embed an SCT, and skipping the check would
// accept a cert Fulcio never actually vouched for via the CT log. Tests pass
// true because ca.VirtualSigstore (github.com/sigstore/sigstore-go's own
// in-memory test CA, which stubs CTLogs() to satisfy the TrustedMaterial
// interface but never embeds SCTs into the certs it issues) can't otherwise
// exercise the rest of the verification pipeline.
func applyKeylessVerification(ctx context.Context, p *Provenance, raw RawArtifacts, cfg trust.Config, imageDigest string, ignoreSCT bool) {
	if cfg.Identity == "" || cfg.Issuer == "" {
		return
	}
	if !raw.SigPresent && !raw.AttPresent {
		return
	}

	trustedMaterial, err := trustedMaterialProvider(ctx)
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
		IgnoreSCT:       ignoreSCT,
	}

	checked := false
	verified := true
	if raw.SigPresent {
		checked = true
		verified = verified && verifyOCISignature(ctx, raw, h, baseOpts)
	}
	if raw.AttPresent && raw.AttArtifactType != inTotoArtifactType {
		// Raw in-toto atts (buildkit-native) carry no envelope signature and are
		// excluded from cryptographic verification, matching applyVerification.
		checked = true
		verified = verified && verifyOCIAttestation(ctx, raw, h, baseOpts)
	}
	if !checked {
		// Only raw in-toto attestations are present — nothing was actually
		// verified. Leave p.Verified nil (falls through to "signed") and do
		// not name a signer whose certificate was never checked.
		return
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
