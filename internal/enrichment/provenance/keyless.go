package provenance

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	commonv1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	rekorv1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
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

// cosignBundleAnnotation is the JSON shape of the dev.sigstore.cosign/bundle
// annotation, carrying the full offline Rekor inclusion promise (SET) so
// verification never needs a live call to rekor.sigstore.dev.
type cosignBundleAnnotation struct {
	SignedEntryTimestamp string `json:"SignedEntryTimestamp"`
	Payload              struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	} `json:"Payload"`
}

// applyKeylessVerification sets p.Verified based on Fulcio certificate chain +
// Rekor transparency log verification (sigstore-go), using the OIDC identity/issuer
// configured on the registry (cfg.Identity is a regex, cfg.Issuer an exact match).
//
// Verification is entirely offline: the Rekor inclusion promise (SET) embedded in
// cosign's OCI bundle annotation is verified against the trusted root's Rekor
// public key, with no live call to rekor.sigstore.dev.
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

	certID, err := buildCertificateIdentity(cfg)
	if err != nil {
		slog.ErrorContext(ctx, "keyless verification: building certificate identity", "err", err)
		return
	}

	sev, err := verify.NewVerifier(trustedMaterial,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		slog.ErrorContext(ctx, "keyless verification: constructing verifier", "err", err)
		return
	}

	verified := true
	if raw.SigPresent {
		ok := verifyKeylessMessageSignature(sev, certID, raw, imageDigest)
		verified = verified && ok
	}
	if raw.AttPresent && raw.AttArtifactType != inTotoArtifactType {
		// Raw in-toto atts (buildkit-native) carry no envelope signature and are
		// excluded from cryptographic verification, matching applyVerification.
		ok := verifyKeylessDSSEAttestation(sev, certID, raw, imageDigest)
		verified = verified && ok
	}
	p.Verified = &verified
	if verified {
		p.SignerIdentity = cfg.Identity
		p.SignerIssuer = cfg.Issuer
	}
}

// buildCertificateIdentity turns the registry's configured identity (SAN regex)
// and issuer (exact match) into a sigstore-go policy matcher.
func buildCertificateIdentity(cfg TrustConfig) (verify.CertificateIdentity, error) {
	sanMatcher, err := verify.NewSANMatcher("", cfg.Identity)
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("compiling trust_identity regex: %w", err)
	}
	issuerMatcher, err := verify.NewIssuerMatcher(cfg.Issuer, "")
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("building issuer matcher: %w", err)
	}
	return verify.NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{})
}

// verifyKeylessMessageSignature verifies the cosign simplesigning signature
// (the OCI-attached image signature) against a Fulcio cert + Rekor bundle.
func verifyKeylessMessageSignature(sev *verify.Verifier, certID verify.CertificateIdentity, raw RawArtifacts, imageDigest string) bool {
	certPEM := raw.SigAnnotations["dev.sigstore.cosign/certificate"]
	sigBase64 := raw.SigAnnotations["dev.cosignproject.cosign/signature"]
	if certPEM == "" || sigBase64 == "" || len(raw.SigLayerBytes) == 0 {
		return false
	}
	certDER, err := pemToDER(certPEM)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return false
	}
	tlogEntry, err := buildTlogEntry(raw.SigAnnotations["dev.sigstore.cosign/bundle"], "hashedrekord")
	if err != nil {
		return false
	}

	digest := sigBoundDigest(raw.SigLayerBytes)
	if digest == "" || digest != imageDigest {
		return false
	}

	pbBundle := &protobundle.Bundle{
		MediaType: bundleArtifactType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content:     &protobundle.VerificationMaterial_Certificate{Certificate: &commonv1.X509Certificate{RawBytes: certDER}},
			TlogEntries: []*rekorv1.TransparencyLogEntry{tlogEntry},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &commonv1.MessageSignature{
				Signature: sig,
			},
		},
	}

	b, err := bundle.NewBundle(pbBundle)
	if err != nil {
		return false
	}

	digestBytes, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if err != nil {
		return false
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha256", digestBytes), verify.WithCertificateIdentity(certID))
	_, err = sev.Verify(b, policy)
	return err == nil
}

// verifyKeylessDSSEAttestation verifies a DSSE-enveloped SLSA attestation against
// a Fulcio cert + Rekor bundle, requiring the envelope's subject to bind to imageDigest.
func verifyKeylessDSSEAttestation(sev *verify.Verifier, certID verify.CertificateIdentity, raw RawArtifacts, imageDigest string) bool {
	certPEM := raw.AttAnnotations["dev.sigstore.cosign/certificate"]
	if certPEM == "" || len(raw.AttLayerBytes) == 0 {
		return false
	}
	certDER, err := pemToDER(certPEM)
	if err != nil {
		return false
	}
	var env dsseEnvelope
	if err := json.Unmarshal(raw.AttLayerBytes, &env); err != nil || len(env.Signatures) == 0 {
		return false
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return false
	}
	tlogEntry, err := buildTlogEntry(raw.AttAnnotations["dev.sigstore.cosign/bundle"], "intoto")
	if err != nil {
		return false
	}

	pbBundle := &protobundle.Bundle{
		MediaType: bundleArtifactType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content:     &protobundle.VerificationMaterial_Certificate{Certificate: &commonv1.X509Certificate{RawBytes: certDER}},
			TlogEntries: []*rekorv1.TransparencyLogEntry{tlogEntry},
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     payload,
				PayloadType: env.PayloadType,
				Signatures:  []*protodsse.Signature{{Sig: sig, Keyid: env.Signatures[0].KeyID}},
			},
		},
	}

	b, err := bundle.NewBundle(pbBundle)
	if err != nil {
		return false
	}

	// Belt-and-suspenders: verify the subject binding ourselves in addition to
	// the policy's digest check below, mirroring applyVerification's public-key path.
	var stmt inTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil || !subjectsBindTo(subjectsOf(stmt), imageDigest) {
		return false
	}

	digestBytes, err := hex.DecodeString(strings.TrimPrefix(imageDigest, "sha256:"))
	if err != nil {
		return false
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha256", digestBytes), verify.WithCertificateIdentity(certID))
	_, err = sev.Verify(b, policy)
	return err == nil
}

// subjectsOf extracts "name@sha256:digest" strings from an in-toto statement,
// mirroring extractFromDSSE's subject handling.
func subjectsOf(stmt inTotoStatement) []string {
	var subjects []string
	for _, s := range stmt.Subject {
		if sha, ok := s.Digest["sha256"]; ok {
			subjects = append(subjects, s.Name+"@sha256:"+sha)
		}
	}
	return subjects
}

// buildTlogEntry converts cosign's dev.sigstore.cosign/bundle annotation (the
// offline Rekor inclusion promise) into a sigstore-go TransparencyLogEntry.
func buildTlogEntry(bundleJSON, kind string) (*rekorv1.TransparencyLogEntry, error) {
	if bundleJSON == "" {
		return nil, fmt.Errorf("no cosign bundle annotation present")
	}
	var b cosignBundleAnnotation
	if err := json.Unmarshal([]byte(bundleJSON), &b); err != nil {
		return nil, fmt.Errorf("parsing cosign bundle annotation: %w", err)
	}
	if b.Payload.LogID == "" || b.Payload.Body == "" || b.SignedEntryTimestamp == "" {
		return nil, fmt.Errorf("cosign bundle annotation missing required fields")
	}
	logID, err := hex.DecodeString(b.Payload.LogID)
	if err != nil {
		return nil, fmt.Errorf("decoding logID: %w", err)
	}
	canonicalBody, err := base64.StdEncoding.DecodeString(b.Payload.Body)
	if err != nil {
		return nil, fmt.Errorf("decoding canonicalized body: %w", err)
	}
	set, err := base64.StdEncoding.DecodeString(b.SignedEntryTimestamp)
	if err != nil {
		return nil, fmt.Errorf("decoding signed entry timestamp: %w", err)
	}
	return &rekorv1.TransparencyLogEntry{
		LogIndex:          b.Payload.LogIndex,
		LogId:             &commonv1.LogId{KeyId: logID},
		KindVersion:       &rekorv1.KindVersion{Kind: kind, Version: "0.0.1"},
		IntegratedTime:    b.Payload.IntegratedTime,
		InclusionPromise:  &rekorv1.InclusionPromise{SignedEntryTimestamp: set},
		CanonicalizedBody: canonicalBody,
	}, nil
}

func pemToDER(pemStr string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return block.Bytes, nil
}
