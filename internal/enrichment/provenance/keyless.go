package provenance

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/empty"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
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
//
// WithDisableLocalCache is sigstore-go's read-only-filesystem mode. Without it,
// DefaultOptions caches TUF metadata under $HOME/.sigstore/root — or os.TempDir()
// when HOME is unset — and both are read-only under the chart's
// securityContext.readOnlyRootFilesystem, so every keyless verification would
// fail on a filesystem error rather than on trust (ocidex-gsip). The disk cache
// buys little here regardless: trustedRootCache already holds the fetched root
// in process for trustedRootCacheTTL, so this costs one extra fetch per TTL per
// pod.
var fetchTrustedRootFn = func(ctx context.Context) (*root.TrustedRoot, error) {
	return root.FetchTrustedRootWithOptions(
		tuf.DefaultOptions().
			WithContext(ctx).
			WithDisableLocalCache(),
	)
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
// delegated to cosign's own verify pipeline (github.com/sigstore/cosign/v3) —
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
	if !raw.SigPresent() && !raw.AttPresent() {
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
	if raw.SigPresent() {
		checked = true
		if idx := verifyOCISignatures(ctx, raw.Sigs, h, baseOpts); idx >= 0 {
			restampFromSig(p, raw.Sigs[idx])
		} else {
			verified = false
		}
	}
	if atts := raw.verifiableAtts(); len(atts) > 0 {
		// Raw in-toto atts (buildkit-native) carry no envelope signature and are
		// excluded from cryptographic verification, matching applyVerification.
		checked = true
		verified = verified && verifyOCIAttestations(ctx, atts, h, baseOpts) >= 0
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

// verifyOCISignatures reports the index of the first signature layer that
// verifies against co, or -1 when none do.
//
// An image may carry a signature per signer, and only one of them needs to
// satisfy the configured identity — cosign's own VerifyImageSignatures accepts
// an image when any attached signature does. Checking only the first is what
// made every promoted registry.k8s.io image read as "verification failed":
// Kubernetes signs at build as krel-staging and re-signs on promotion as
// krel-trust, the staging signature is listed first, and consumers configure the
// promotion identity (ocidex-r27f).
//
// Shared by the keyless (co.TrustedMaterial) and public-key (co.SigVerifier)
// paths — co determines which trust source is actually checked.
func verifyOCISignatures(ctx context.Context, sigs []signedLayer, h v1.Hash, co cosign.CheckOpts) int {
	co.ClaimVerifier = cosign.SimpleClaimVerifier
	for i, layer := range sigs {
		if layer.ArtifactType == bundleArtifactType {
			if err := verifyBundleLayer(ctx, layer.Bytes, h, co); err != nil {
				logRejection(ctx, "signature", i, len(sigs), err)
				continue
			}
			return i
		}
		sig, err := buildOCISignature(layer.Bytes, layer.Annotations)
		if err != nil {
			logRejection(ctx, "signature", i, len(sigs), err)
			continue
		}
		if _, err := cosign.VerifyImageSignature(ctx, sig, h, &co); err != nil {
			logRejection(ctx, "signature", i, len(sigs), err)
			continue
		}
		return i
	}
	return -1
}

// verifyOCIAttestations reports the index of the first DSSE-enveloped SLSA
// attestation that verifies against co, or -1 when none do. It uses
// IntotoSubjectClaimVerifier to require the envelope's in-toto subject to bind
// to h. Callers pass only the attestations worth verifying (see
// RawArtifacts.verifiableAtts). Plural for the same reason
// verifyOCISignatures is.
func verifyOCIAttestations(ctx context.Context, atts []signedLayer, h v1.Hash, co cosign.CheckOpts) int {
	co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	for i, layer := range atts {
		if layer.ArtifactType == bundleArtifactType {
			if err := verifyBundleLayer(ctx, layer.Bytes, h, co); err != nil {
				logRejection(ctx, "attestation", i, len(atts), err)
				continue
			}
			return i
		}
		att, err := static.NewAttestation(layer.Bytes, buildStaticOptions(layer.Annotations)...)
		if err != nil {
			logRejection(ctx, "attestation", i, len(atts), err)
			continue
		}
		wrapped, err := mutate.AppendSignatures(empty.Signatures(), false, att)
		if err != nil {
			logRejection(ctx, "attestation", i, len(atts), err)
			continue
		}
		if _, _, err := cosign.VerifyImageAttestation(ctx, wrapped, h, &co); err != nil {
			logRejection(ctx, "attestation", i, len(atts), err)
			continue
		}
		return i
	}
	return -1
}

// verifyBundleLayer verifies one new-format Sigstore bundle
// (application/vnd.dev.sigstore.bundle.v0.3+json). The certificate and Rekor
// entry live inside the blob rather than in layer annotations, so
// buildStaticOptions finds nothing to attach and the static.New* path rejects
// every such layer for want of material it can never see.
//
// verify.WithArtifactDigest takes over the job co.ClaimVerifier does on the
// legacy path — binding the signed subject to the digest being enriched — so a
// valid bundle transplanted from another image is still rejected. Both trust
// tiers are already covered by co: CheckOpts.verificationOptions() derives the
// keyless identity policy from co.Identities and honours the public-key tier's
// SigVerifier plus IgnoreTlog.
func verifyBundleLayer(ctx context.Context, data []byte, h v1.Hash, co cosign.CheckOpts) error {
	var b sgbundle.Bundle
	if err := b.UnmarshalJSON(data); err != nil {
		return fmt.Errorf("parsing sigstore bundle: %w", err)
	}
	digestBytes, err := hex.DecodeString(h.Hex)
	if err != nil {
		return fmt.Errorf("decoding image digest: %w", err)
	}
	_, err = cosign.VerifyNewBundle(ctx, &co, verify.WithArtifactDigest(h.Algorithm, digestBytes), &b)
	return err
}

// logRejection records why one layer failed to verify. cosign's error used to be
// discarded, which left "Verification failed" in the UI with no route to a cause
// short of pulling the manifest and decoding certificates by hand. Warn rather
// than error: on a multiply signed image the losing signatures are expected to
// fail, and only the caller knows whether any of them succeeded.
func logRejection(ctx context.Context, kind string, i, total int, err error) {
	slog.WarnContext(ctx, "provenance verification: "+kind+" rejected",
		"layer", i, "of", total, "err", err)
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
// (github.com/sigstore/cosign/v3/pkg/oci/static WithBundle marshals it
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
