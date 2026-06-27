// Package provenance implements signature and attestation discovery for container images.
// It finds cosign signatures and SLSA provenance attached to images in OCI registries,
// using the OCI 1.1 referrers API with a fallback to the cosign tag scheme.
package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/pfenerty/ocidex/internal/enrichment"
)

const (
	enricherName = "provenance"

	// OCI artifact types used by cosign / Tekton Chains.
	sigArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"
	attArtifactType = "application/vnd.dsse.envelope.v1+json"
)

// RawArtifacts is the result stored in the enrichment JSONB column for B2.
// B3 replaces Enrich() to return a parsed Provenance struct built from these fields.
type RawArtifacts struct {
	SigPresent      bool              `json:"sigPresent"`
	SigAnnotations  map[string]string `json:"sigAnnotations,omitempty"`
	SigLayerBytes   []byte            `json:"sigLayerBytes,omitempty"` // simplesigning JSON payload
	AttPresent      bool              `json:"attPresent"`
	AttAnnotations  map[string]string `json:"attAnnotations,omitempty"`
	AttLayerBytes   []byte            `json:"attLayerBytes,omitempty"` // raw DSSE envelope
	DiscoveryMethod string            `json:"discoveryMethod"`         // "referrers" | "tag-scheme"
}

// Enricher discovers cosign signatures and attestations for container images.
type Enricher struct {
	timeout            time.Duration
	options            []remote.Option
	insecure           bool
	insecureResolver   func(ctx context.Context, host string) bool
	credentialResolver func(ctx context.Context, host string) (username, token string)
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

// NewEnricher creates a provenance enricher.
func NewEnricher(opts ...Option) *Enricher {
	e := &Enricher{timeout: 30 * time.Second}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Name returns the enricher identifier.
func (e *Enricher) Name() string { return enricherName }

// CanEnrich returns true for container-type artifacts with a digest.
func (e *Enricher) CanEnrich(ref enrichment.SubjectRef) bool {
	return ref.ArtifactType == "container" && ref.Digest != ""
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
func (e *Enricher) Enrich(ctx context.Context, ref enrichment.SubjectRef) ([]byte, error) {
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

	imageRef := ref.ArtifactName + "@" + ref.Digest
	parsedRef, err := name.ParseReference(imageRef, nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing image ref %q: %w", imageRef, err)
	}
	repo := parsedRef.Context()

	digestRef, ok := parsedRef.(name.Digest)
	if !ok {
		return nil, fmt.Errorf("expected digest reference for %q", imageRef)
	}

	// Build remote options (same pattern as internal/enrichment/oci/oci.go).
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

	result := e.discover(ctx, digestRef, repo, ref.Digest, opts)

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshaling provenance artifacts: %w", err)
	}
	return data, nil
}

// discover tries the OCI 1.1 referrers API first, then falls back to the cosign tag scheme.
func (e *Enricher) discover(ctx context.Context, digestRef name.Digest, repo name.Repository, rawDigest string, opts []remote.Option) RawArtifacts {
	// OCI 1.1 referrers API (go-containerregistry also tries the sha256-<hex> fallback tag internally).
	idx, err := remote.Referrers(digestRef, opts...)
	if err == nil {
		if result, found := e.extractFromReferrers(idx, repo, opts); found {
			return result
		}
	}
	// Cosign tag scheme: sha256-<hex>.sig and sha256-<hex>.att
	return e.discoverViaTagScheme(repo, rawDigest, opts)
}

// extractFromReferrers iterates a referrers index and extracts sig/att artifacts.
// go-containerregistry's remoteIndex.Image() panics when called on a referrers index
// (the ref field is unset), so child images are fetched directly via remote.Image().
func (e *Enricher) extractFromReferrers(idx v1.ImageIndex, repo name.Repository, opts []remote.Option) (RawArtifacts, bool) {
	idxManifest, err := idx.IndexManifest()
	if err != nil {
		return RawArtifacts{}, false
	}

	var result RawArtifacts
	result.DiscoveryMethod = "referrers"

	for _, desc := range idxManifest.Manifests {
		switch string(desc.ArtifactType) {
		case sigArtifactType:
			if result.SigPresent {
				continue // take first sig only
			}
			childRef := repo.Digest(desc.Digest.String())
			img, err := remote.Image(childRef, opts...)
			if err != nil {
				continue
			}
			result.SigAnnotations = manifestAnnotations(img)
			result.SigLayerBytes, _ = readFirstLayer(img)
			result.SigPresent = true

		case attArtifactType:
			if result.AttPresent {
				continue // take first att only
			}
			childRef := repo.Digest(desc.Digest.String())
			img, err := remote.Image(childRef, opts...)
			if err != nil {
				continue
			}
			result.AttAnnotations = manifestAnnotations(img)
			result.AttLayerBytes, _ = readFirstLayer(img)
			result.AttPresent = true
		}
	}

	return result, result.SigPresent || result.AttPresent
}

// discoverViaTagScheme fetches sha256-<hex>.sig and sha256-<hex>.att tags from the same repo.
func (e *Enricher) discoverViaTagScheme(repo name.Repository, rawDigest string, opts []remote.Option) RawArtifacts {
	hexDigest := strings.Replace(rawDigest, ":", "-", 1) // sha256:abc → sha256-abc

	var result RawArtifacts
	result.DiscoveryMethod = "tag-scheme"

	sigRef := repo.Tag(hexDigest + ".sig")
	if img, err := remote.Image(sigRef, opts...); err == nil {
		result.SigAnnotations = manifestAnnotations(img)
		result.SigLayerBytes, _ = readFirstLayer(img)
		result.SigPresent = true
	}

	attRef := repo.Tag(hexDigest + ".att")
	if img, err := remote.Image(attRef, opts...); err == nil {
		result.AttAnnotations = manifestAnnotations(img)
		result.AttLayerBytes, _ = readFirstLayer(img)
		result.AttPresent = true
	}

	return result
}

// manifestAnnotations returns the annotations from an image's manifest, or nil on error.
func manifestAnnotations(img v1.Image) map[string]string {
	m, err := img.Manifest()
	if err != nil || m == nil {
		return nil
	}
	return m.Annotations
}

// readFirstLayer reads and returns the raw bytes of the first layer in an image.
func readFirstLayer(img v1.Image) ([]byte, error) {
	layers, err := img.Layers()
	if err != nil || len(layers) == 0 {
		return nil, err
	}
	rc, err := layers[0].Compressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}
