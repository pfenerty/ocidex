package provenance

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
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
// Rekor transparency log verification. Discovery and cryptographic verification
// are delegated to cosign's own verify pipeline (github.com/sigstore/cosign/v2) —
// the reference implementation for exactly this check, rather than hand-parsing
// cosign's OCI annotations and reassembling a Sigstore bundle ourselves.
//
// Verification is offline (co.Offline: true): cosign verifies the Rekor
// inclusion promise (SET) embedded in its own OCI bundle annotation against
// trustedMaterial's Rekor public key, with no live call to rekor.sigstore.dev.
func applyKeylessVerification(ctx context.Context, p *Provenance, raw RawArtifacts, cfg TrustConfig, digestRef name.Digest, remoteOpts []remote.Option) {
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

	co := &cosign.CheckOpts{
		TrustedMaterial:    trustedMaterial,
		Identities:         []cosign.Identity{{SubjectRegExp: cfg.Identity, Issuer: cfg.Issuer}},
		Offline:            true,
		RegistryClientOpts: []ociremote.Option{ociremote.WithRemoteOptions(remoteOpts...)},
	}

	verified := true
	if raw.SigPresent {
		_, _, err := cosign.VerifyImageSignatures(ctx, digestRef, co)
		verified = verified && err == nil
	}
	if raw.AttPresent && raw.AttArtifactType != inTotoArtifactType {
		// Raw in-toto atts (buildkit-native) carry no envelope signature and are
		// excluded from cryptographic verification, matching applyVerification.
		_, _, err := cosign.VerifyImageAttestations(ctx, digestRef, co)
		verified = verified && err == nil
	}
	p.Verified = &verified
	if verified {
		p.SignerIdentity = cfg.Identity
		p.SignerIssuer = cfg.Issuer
	}
}
