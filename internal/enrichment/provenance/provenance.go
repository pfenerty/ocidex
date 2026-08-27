// Package provenance implements signature and attestation discovery for container images.
// It finds cosign signatures and SLSA provenance attached to images in OCI registries,
// using the OCI 1.1 referrers API with a fallback to the cosign tag scheme.
package provenance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/enrichment/names"
	"github.com/pfenerty/ocidex/internal/enrichment/subject"
	"github.com/pfenerty/ocidex/internal/trust"
)

const (
	enricherName = names.Provenance

	// OCI artifact types used by cosign / Tekton Chains / buildkit.
	sigArtifactType    = "application/vnd.dev.cosign.artifact.sig.v1+json"
	attArtifactType    = "application/vnd.dsse.envelope.v1+json"
	inTotoArtifactType = "application/vnd.in-toto+json"
	bundleArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// defaultMaxLayerBytes caps a single signature or attestation layer read.
	// The layer is registry-controlled and read whole into memory: a bare cosign
	// signature is a few KB, but an attestation carrying a full SBOM is
	// megabytes, and reading one unbounded is what OOMKilled this worker
	// (ocidex-wvnp). 16MiB is far above any legitimate compressed attestation
	// while staying small enough that several concurrent reads fit the pod's
	// memory limit. Raising it means raising that limit too.
	defaultMaxLayerBytes = 16 << 20
)

// ErrLayerTooLarge is returned when a signature or attestation layer exceeds the
// configured cap. It fails that one enrichment job — which lands in
// enrichment_jobs with a diagnosable reason — rather than exhausting the pod.
var ErrLayerTooLarge = errors.New("layer exceeds maximum size")

// RawArtifacts is the result stored in the enrichment JSONB column for B2.
// B3 replaces Enrich() to return a parsed Provenance struct built from these fields.
type RawArtifacts struct {
	SigPresent      bool              `json:"sigPresent"`
	SigAnnotations  map[string]string `json:"sigAnnotations,omitempty"`
	SigLayerBytes   []byte            `json:"sigLayerBytes,omitempty"` // simplesigning JSON payload
	AttPresent      bool              `json:"attPresent"`
	AttAnnotations  map[string]string `json:"attAnnotations,omitempty"`
	AttLayerBytes   []byte            `json:"attLayerBytes,omitempty"`   // raw DSSE envelope or raw in-toto statement
	AttArtifactType string            `json:"attArtifactType,omitempty"` // attArtifactType | inTotoArtifactType; empty means DSSE
	DiscoveryMethod string            `json:"discoveryMethod"`           // "referrers" | "tag-scheme"
	ArtifactMissing bool              `json:"artifactMissing,omitempty"` // true when the registry no longer has this digest
}

// TrustResolver returns the verification configuration for the given registry.
// host is retained as a fallback for callers that cannot supply a registry ID.
type TrustResolver func(ctx context.Context, registryID pgtype.UUID, host string) trust.Config

// Enricher discovers cosign signatures and attestations for container images.
type Enricher struct {
	timeout            time.Duration
	options            []remote.Option
	insecure           bool
	insecureResolver   func(ctx context.Context, host string) bool
	credentialResolver func(ctx context.Context, host string) (username, token string)
	trustResolver      TrustResolver
	maxLayerBytes      int64
}

// Option configures the provenance Enricher.
type Option func(*Enricher)

// WithTimeout sets the per-enrichment timeout.
func WithTimeout(d time.Duration) Option {
	return func(e *Enricher) { e.timeout = d }
}

// WithRemoteOptions appends additional go-containerregistry remote options.
func WithRemoteOptions(opts ...remote.Option) Option {
	return func(e *Enricher) { e.options = append(e.options, opts...) }
}

// WithInsecure configures plain HTTP for all registry connections.
func WithInsecure() Option {
	return func(e *Enricher) { e.insecure = true }
}

// WithInsecureResolver sets a per-host function that returns true when plain HTTP should be used.
// Takes precedence over WithInsecure.
func WithInsecureResolver(fn func(ctx context.Context, host string) bool) Option {
	return func(e *Enricher) { e.insecureResolver = fn }
}

// WithCredentialResolver sets a function that resolves registry credentials by hostname.
func WithCredentialResolver(fn func(ctx context.Context, host string) (username, token string)) Option {
	return func(e *Enricher) { e.credentialResolver = fn }
}

// WithMaxLayerBytes caps how many bytes a single signature or attestation layer
// may contribute. A layer larger than this fails that enrichment with
// ErrLayerTooLarge instead of being read into memory. Values <= 0 are ignored.
func WithMaxLayerBytes(n int64) Option {
	return func(e *Enricher) {
		if n > 0 {
			e.maxLayerBytes = n
		}
	}
}

// WithTrustResolver sets the per-host trust configuration resolver used for ECDSA verification.
func WithTrustResolver(fn TrustResolver) Option {
	return func(e *Enricher) { e.trustResolver = fn }
}

// NewEnricher creates a provenance enricher.
func NewEnricher(opts ...Option) *Enricher {
	e := &Enricher{timeout: 30 * time.Second, maxLayerBytes: defaultMaxLayerBytes}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Name returns the enricher identifier.
func (e *Enricher) Name() string { return enricherName }

// CanEnrich returns true for container-type artifacts with a digest that
// arrived through a registry-backed source. An upload source has no registry
// row and so no manifest to fetch signatures against — that is a "not
// applicable", not a failure, so it is filtered here rather than erroring in
// Enrich (ADR-039).
func (e *Enricher) CanEnrich(ref subject.Ref) bool {
	if ref.SourceKind == subject.KindUpload {
		return false
	}
	return ref.ArtifactType == subject.TypeContainer && ref.Digest != ""
}

// insecureFor returns true when the given host should be contacted over plain HTTP.
func (e *Enricher) insecureFor(ctx context.Context, host string) bool {
	if e.insecureResolver != nil && e.insecureResolver(ctx, host) {
		return true
	}
	return e.insecure
}

// Enrich discovers cosign signatures and attestations for the image digest and
// returns a JSON-encoded RawArtifacts. Returns an error only for fatal failures
// (bad reference, marshal error); missing sig/att results in SigPresent=false/AttPresent=false.
func (e *Enricher) Enrich(ctx context.Context, ref subject.Ref) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Extract host for per-host insecure and credential resolution.
	host := ref.ArtifactName
	if i := strings.Index(host, "/"); i != -1 {
		host = host[:i]
	}

	nameOpts := []name.Option{}
	if e.insecureFor(ctx, host) {
		nameOpts = append(nameOpts, name.Insecure)
	}

	// cosign/Tekton Chains sign the multi-arch image index (the tag target), not
	// the per-platform child manifest. When this SBOM was expanded from an index,
	// look up provenance on the index digest; otherwise use the image's own digest.
	lookupDigest := ref.Digest
	if ref.IndexDigest != "" {
		lookupDigest = ref.IndexDigest
	}

	imageRef := ref.ArtifactName + "@" + lookupDigest
	parsedRef, err := name.ParseReference(imageRef, nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing image ref %q: %w", imageRef, err)
	}
	repo := parsedRef.Context()

	digestRef, ok := parsedRef.(name.Digest)
	if !ok {
		return nil, fmt.Errorf("expected digest reference for %q", imageRef)
	}

	opts := e.buildRemoteOptions(ctx, host)

	// Confirm the digest still exists before discovering sig/att data. Without
	// this, a deleted image and a never-signed image are indistinguishable:
	// discover()'s referrers/tag-scheme lookups fail the same way for both,
	// silently downgrading a drift event (verified -> gone) to "unsigned".
	missing, err := artifactMissing(digestRef, opts)
	if err != nil {
		return nil, fmt.Errorf("checking artifact existence for %q: %w", imageRef, err)
	}
	if missing {
		data, err := json.Marshal(buildProvenance(RawArtifacts{ArtifactMissing: true}))
		if err != nil {
			return nil, fmt.Errorf("marshaling provenance: %w", err)
		}
		return data, nil
	}

	raw, err := e.discover(digestRef, repo, lookupDigest, opts)
	if err != nil {
		return nil, fmt.Errorf("discovering provenance for %q: %w", imageRef, err)
	}
	p := buildProvenance(raw)
	if p.RekorLogIndex > 0 {
		p.RekorUUID = fetchRekorUUID(ctx, p.RekorLogIndex)
	}
	if e.trustResolver != nil {
		e.applyTrust(ctx, &p, raw, ref.RegistryID, host, lookupDigest)
	}

	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshaling provenance: %w", err)
	}
	return data, nil
}

// buildRemoteOptions assembles go-containerregistry remote options for host,
// including per-host credentials (same pattern as internal/enrichment/oci/oci.go).
func (e *Enricher) buildRemoteOptions(ctx context.Context, host string) []remote.Option {
	opts := make([]remote.Option, 0, len(e.options)+2)
	opts = append(opts, remote.WithContext(ctx))
	opts = append(opts, e.options...)
	if e.credentialResolver != nil {
		if u, t := e.credentialResolver(ctx, host); u != "" || t != "" {
			opts = append(opts, remote.WithAuth(authn.FromConfig(authn.AuthConfig{
				Username: u,
				Password: t,
			})))
		}
	}
	return opts
}

// applyTrust dispatches to the configured verification mode's checker.
func (e *Enricher) applyTrust(ctx context.Context, p *Provenance, raw RawArtifacts, registryID pgtype.UUID, host, imageDigest string) {
	cfg := e.trustResolver(ctx, registryID, host)
	switch cfg.Mode {
	case trust.ModePublicKey:
		applyVerification(ctx, p, raw, cfg.Mode, cfg.PublicKeyPEM, imageDigest)
	case trust.ModeKeyless:
		applyKeylessVerification(ctx, p, raw, cfg, imageDigest, false)
	}
}

// isNotFound reports whether err is a registry 404 (MANIFEST_UNKNOWN /
// NAME_UNKNOWN), i.e. positive evidence that the thing being fetched does not
// exist. Every other failure — 401, 429, 5xx, TLS, context deadline — is
// transient and says nothing about existence. Discovery must not confuse the
// two: doing so turns a rate-limited recheck into a false "unsigned" and, in
// turn, a false verified -> unsigned drift event.
func isNotFound(err error) bool {
	var terr *transport.Error
	return errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound
}

// artifactMissing reports whether digestRef no longer exists in the registry
// (404/MANIFEST_UNKNOWN). Any other error (network, auth, 5xx) is returned as
// an error so the caller treats it as transient rather than deletion.
func artifactMissing(digestRef name.Digest, opts []remote.Option) (bool, error) {
	if _, err := remote.Head(digestRef, opts...); err != nil {
		if isNotFound(err) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// discover tries the OCI 1.1 referrers API first, then falls back to the cosign tag scheme.
//
// A Referrers error is deliberately NOT fatal: registries that don't implement
// OCI 1.1 reject the endpoint with assorted non-404 codes, so the error is no
// evidence either way and the tag scheme is still worth trying. Once we reach
// the tag scheme, though, its result is authoritative — a transient failure
// there is returned as an error rather than reported as "no signature".
func (e *Enricher) discover(digestRef name.Digest, repo name.Repository, rawDigest string, opts []remote.Option) (RawArtifacts, error) {
	// OCI 1.1 referrers API (go-containerregistry also tries the sha256-<hex> fallback tag internally).
	idx, err := remote.Referrers(digestRef, opts...)
	if err == nil {
		result, found, extractErr := e.extractFromReferrers(idx, repo, opts)
		if extractErr != nil {
			return RawArtifacts{}, extractErr
		}
		if found {
			return result, nil
		}
	}
	// Cosign tag scheme: sha256-<hex>.sig and sha256-<hex>.att
	return e.discoverViaTagScheme(repo, rawDigest, opts)
}

// extractFromReferrers iterates a referrers index and extracts sig/att artifacts.
// go-containerregistry's remoteIndex.Image() panics when called on a referrers index
// (the ref field is unset), so child images are fetched directly via remote.Image().
func (e *Enricher) extractFromReferrers(idx v1.ImageIndex, repo name.Repository, opts []remote.Option) (RawArtifacts, bool, error) {
	idxManifest, err := idx.IndexManifest()
	if err != nil {
		return RawArtifacts{}, false, fmt.Errorf("reading referrers index: %w", err)
	}

	var result RawArtifacts
	result.DiscoveryMethod = "referrers"

	for _, desc := range idxManifest.Manifests {
		switch desc.ArtifactType {
		case sigArtifactType:
			if result.SigPresent {
				continue // take first sig only
			}
			annotations, layerBytes, err := fetchReferrerLayer(repo, desc, opts, e.maxLayerBytes)
			if isNotFound(err) {
				continue // dangling index entry; the tag scheme gets the final say
			}
			if err != nil {
				return RawArtifacts{}, false, err
			}
			result.SigAnnotations = annotations
			result.SigLayerBytes = layerBytes
			result.SigPresent = true

		case attArtifactType, inTotoArtifactType, bundleArtifactType:
			if result.AttPresent {
				continue // take first att only; prefer earlier-listed match if multiple present
			}
			annotations, layerBytes, err := fetchReferrerLayer(repo, desc, opts, e.maxLayerBytes)
			if isNotFound(err) {
				continue // dangling index entry; the tag scheme gets the final say
			}
			if err != nil {
				return RawArtifacts{}, false, err
			}
			result.AttAnnotations = annotations
			result.AttLayerBytes = layerBytes
			result.AttPresent = true
			result.AttArtifactType = desc.ArtifactType
		}
	}

	return result, result.SigPresent || result.AttPresent, nil
}

// fetchReferrerLayer fetches a referrer's child image and returns its merged
// manifest annotations and first-layer bytes. go-containerregistry's
// remoteIndex.Image() panics when called on a referrers index (the ref field
// is unset), so child images are fetched directly via remote.Image().
//
// Failures here do not mean "unsigned": the referrers index has already told us
// this artifact exists, so being unable to fetch it is never evidence of
// absence. Errors propagate rather than degrading to "no signature found". The
// caller makes one exception, for a 404 — an index entry contradicted by the
// manifest store is a dangling entry, not a transient fault, and erroring on it
// would wedge that SBOM's enrichment for as long as the registry stayed
// inconsistent. That case falls back to the tag scheme instead.
func fetchReferrerLayer(repo name.Repository, desc v1.Descriptor, opts []remote.Option, maxLayerBytes int64) (annotations map[string]string, layerBytes []byte, err error) {
	childRef := repo.Digest(desc.Digest.String())
	img, err := remote.Image(childRef, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching referrer %s: %w", desc.Digest.String(), err)
	}
	layerBytes, err = readFirstLayer(img, maxLayerBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("reading referrer %s layer: %w", desc.Digest.String(), err)
	}
	return manifestAnnotations(img), layerBytes, nil
}

// discoverViaTagScheme fetches sha256-<hex>.sig and sha256-<hex>.att tags from the same repo.
//
// This is the authoritative "is it signed?" answer, so only a 404 counts as
// absent. Any other failure is returned as an error and surfaces as a failed
// enrichment, which the outbox retries — rather than being recorded as a
// successful "unsigned" result.
func (e *Enricher) discoverViaTagScheme(repo name.Repository, rawDigest string, opts []remote.Option) (RawArtifacts, error) {
	hexDigest := strings.Replace(rawDigest, ":", "-", 1) // sha256:abc → sha256-abc

	var result RawArtifacts
	result.DiscoveryMethod = "tag-scheme"

	sigRef := repo.Tag(hexDigest + ".sig")
	img, err := remote.Image(sigRef, opts...)
	switch {
	case err == nil:
		result.SigLayerBytes, err = readFirstLayer(img, e.maxLayerBytes)
		if err != nil {
			return RawArtifacts{}, fmt.Errorf("reading %s layer: %w", sigRef, err)
		}
		result.SigAnnotations = manifestAnnotations(img)
		result.SigPresent = true
	case !isNotFound(err):
		return RawArtifacts{}, fmt.Errorf("fetching %s: %w", sigRef, err)
	}

	attRef := repo.Tag(hexDigest + ".att")
	img, err = remote.Image(attRef, opts...)
	switch {
	case err == nil:
		result.AttLayerBytes, err = readFirstLayer(img, e.maxLayerBytes)
		if err != nil {
			return RawArtifacts{}, fmt.Errorf("reading %s layer: %w", attRef, err)
		}
		result.AttAnnotations = manifestAnnotations(img)
		result.AttPresent = true
	case !isNotFound(err):
		return RawArtifacts{}, fmt.Errorf("fetching %s: %w", attRef, err)
	}

	return result, nil
}

// manifestAnnotations returns merged manifest + layer[0] annotations.
// Cosign stores dev.cosignproject.cosign/signature in the layer descriptor annotations,
// not at the manifest level, so both must be combined.
func manifestAnnotations(img v1.Image) map[string]string {
	m, err := img.Manifest()
	if err != nil || m == nil {
		return nil
	}
	merged := make(map[string]string, len(m.Annotations))
	for k, v := range m.Annotations {
		merged[k] = v
	}
	if len(m.Layers) > 0 {
		for k, v := range m.Layers[0].Annotations {
			merged[k] = v
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

// readFirstLayer reads and returns the raw bytes of the first layer in an image,
// refusing to buffer more than maxBytes of it.
//
// The layer is registry-controlled content, so its size is not ours to trust.
// The descriptor is checked first, which skips the transfer entirely for a layer
// that admits to being oversized; a descriptor that understates the real size is
// still caught by the LimitReader, which never holds more than maxBytes+1.
func readFirstLayer(img v1.Image, maxBytes int64) ([]byte, error) {
	layers, err := img.Layers()
	if err != nil || len(layers) == 0 {
		return nil, err
	}
	if size, sizeErr := layers[0].Size(); sizeErr == nil && size > maxBytes {
		return nil, fmt.Errorf("%w: %d bytes declared, limit is %d", ErrLayerTooLarge, size, maxBytes)
	}
	rc, err := layers[0].Compressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: over %d bytes, limit is %d", ErrLayerTooLarge, maxBytes, maxBytes)
	}
	return data, nil
}
