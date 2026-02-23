// Package oci implements the OCI registry metadata enricher.
// It fetches container image config from OCI-compliant registries
// to extract labels, build timestamps, architecture, and OS information.
package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/pfenerty/ocidex/internal/enrichment"
)

// Metadata is the structured data stored in the enrichment JSONB column.
type Metadata struct {
	Architecture string            `json:"architecture,omitempty"`
	OS           string            `json:"os,omitempty"`
	Created      *time.Time        `json:"created,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	// Raw annotations from manifest and parent index.
	ManifestAnnotations map[string]string `json:"manifestAnnotations,omitempty"`
	IndexAnnotations    map[string]string `json:"indexAnnotations,omitempty"`
	// Convenience fields extracted from well-known OCI annotation keys.
	// Priority: manifest annotations > config labels > index annotations.
	ImageVersion  string `json:"imageVersion,omitempty"`
	SourceURL     string `json:"sourceUrl,omitempty"`
	Revision      string `json:"revision,omitempty"`
	Authors       string `json:"authors,omitempty"`
	Description   string `json:"description,omitempty"`
	BaseName      string `json:"baseName,omitempty"`
	URL           string `json:"url,omitempty"`
	Documentation string `json:"documentation,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
	Licenses      string `json:"licenses,omitempty"`
	Title         string `json:"title,omitempty"`
	BaseDigest    string `json:"baseDigest,omitempty"`
}

// Enricher fetches OCI image metadata from container registries.
type Enricher struct {
	timeout  time.Duration
	options  []remote.Option
	insecure bool
}

// Option configures the OCI Enricher.
type Option func(*Enricher)

// WithTimeout sets the per-request timeout for registry calls.
func WithTimeout(d time.Duration) Option {
	return func(e *Enricher) { e.timeout = d }
}

// WithRemoteOptions sets additional options for the remote client.
func WithRemoteOptions(opts ...remote.Option) Option {
	return func(e *Enricher) { e.options = append(e.options, opts...) }
}

// WithInsecure configures the enricher to use plain HTTP for registry connections.
func WithInsecure() Option {
	return func(e *Enricher) { e.insecure = true }
}

// NewEnricher creates an OCI metadata enricher.
func NewEnricher(opts ...Option) *Enricher {
	e := &Enricher{
		timeout: 30 * time.Second,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Name returns the enricher identifier.
func (e *Enricher) Name() string { return "oci-metadata" }

// CanEnrich returns true for container-type artifacts with a digest.
func (e *Enricher) CanEnrich(ref enrichment.SubjectRef) bool {
	return ref.ArtifactType == "container" && ref.Digest != ""
}

// Enrich fetches the OCI image config and extracts metadata.
// The digest must point to a single image manifest, not an index.
// Index digests are rejected at ingest time by the Validator.
func (e *Enricher) Enrich(ctx context.Context, ref enrichment.SubjectRef) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	imageRef := ref.ArtifactName + "@" + ref.Digest

	nameOpts := []name.Option{}
	if e.insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	parsedRef, err := name.ParseReference(imageRef, nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing image ref %q: %w", imageRef, err)
	}

	opts := make([]remote.Option, 0, len(e.options)+1)
	opts = append(opts, remote.WithContext(ctx))
	opts = append(opts, e.options...)

	desc, err := remote.Get(parsedRef, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetching descriptor for %q: %w", imageRef, err)
	}

	if desc.MediaType.IsIndex() {
		return nil, fmt.Errorf("digest points to manifest list (multi-arch image), not a single image manifest: %s", ref.Digest)
	}

	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("reading image %q: %w", imageRef, err)
	}

	cfgFile, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("reading config for %q: %w", imageRef, err)
	}

	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("reading manifest for %q: %w", imageRef, err)
	}

	var manifestAnnotations map[string]string
	if manifest != nil {
		manifestAnnotations = manifest.Annotations
	}

	indexAnnotations := e.fetchParentIndexAnnotations(ctx, ref, cfgFile.Config.Labels, opts)

	meta := extractMetadata(cfgFile, manifestAnnotations, indexAnnotations)

	data, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshaling metadata: %w", err)
	}

	return data, nil
}

// Validator checks that a container image digest points to a single
// image manifest and not a manifest list (image index).
type Validator struct {
	timeout  time.Duration
	options  []remote.Option
	insecure bool
}

// NewValidator creates an OCI digest validator.
func NewValidator(opts ...Option) *Validator {
	e := &Enricher{timeout: 30 * time.Second}
	for _, o := range opts {
		o(e)
	}
	return &Validator{timeout: e.timeout, options: e.options, insecure: e.insecure}
}

// ValidateDigest verifies that imageName@digest points to a single image
// manifest. Returns an error if it points to a manifest list.
func (v *Validator) ValidateDigest(ctx context.Context, imageName, digest string) error {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	imageRef := imageName + "@" + digest

	nameOpts := []name.Option{}
	if v.insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	parsedRef, err := name.ParseReference(imageRef, nameOpts...)
	if err != nil {
		return fmt.Errorf("parsing image ref %q: %w", imageRef, err)
	}

	opts := make([]remote.Option, 0, len(v.options)+1)
	opts = append(opts, remote.WithContext(ctx))
	opts = append(opts, v.options...)

	desc, err := remote.Get(parsedRef, opts...)
	if err != nil {
		return fmt.Errorf("fetching descriptor for %q: %w", imageRef, err)
	}

	if desc.MediaType.IsIndex() {
		return fmt.Errorf(
			"digest %s is a manifest list (multi-arch image); SBOM must reference a specific platform image manifest, not an image index",
			digest,
		)
	}

	return nil
}

// fetchParentIndexAnnotations performs a best-effort lookup of the parent
// image index for this image and returns its annotations. Returns nil on
// any error — enrichment must never fail because of a missing index.
func (e *Enricher) fetchParentIndexAnnotations(ctx context.Context, ref enrichment.SubjectRef, labels map[string]string, opts []remote.Option) map[string]string {
	// Determine the version tag to look up.
	version := ref.SubjectVersion
	if version == "" {
		version = labels["org.opencontainers.image.version"]
	}
	if version == "" {
		return nil
	}

	// Strip digest from artifact name to get bare repo.
	repo := ref.ArtifactName
	if idx := strings.Index(repo, "@"); idx != -1 {
		repo = repo[:idx]
	}

	nameOpts := []name.Option{}
	if e.insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	tagRef, err := name.ParseReference(repo+":"+version, nameOpts...)
	if err != nil {
		return nil
	}

	indexCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	indexOpts := make([]remote.Option, 0, len(opts))
	indexOpts = append(indexOpts, remote.WithContext(indexCtx))
	// Copy non-context options from the original set (skip index 0 which is the parent context).
	if len(opts) > 1 {
		indexOpts = append(indexOpts, opts[1:]...)
	}

	desc, err := remote.Get(tagRef, indexOpts...)
	if err != nil {
		return nil
	}

	if !desc.MediaType.IsIndex() {
		return nil
	}

	idx, err := desc.ImageIndex()
	if err != nil {
		return nil
	}

	idxManifest, err := idx.IndexManifest()
	if err != nil {
		return nil
	}

	return idxManifest.Annotations
}

// extractField returns the first non-empty value for key across the sources
// in priority order: manifest annotations > config labels > index annotations.
func extractField(key string, manifestAnnotations, labels, indexAnnotations map[string]string) string {
	if v := manifestAnnotations[key]; v != "" {
		return v
	}
	if v := labels[key]; v != "" {
		return v
	}
	if v := indexAnnotations[key]; v != "" {
		return v
	}
	return ""
}

// extractMetadata builds a Metadata struct from all available annotation sources.
func extractMetadata(cfg *v1.ConfigFile, manifestAnnotations, indexAnnotations map[string]string) Metadata {
	meta := Metadata{
		Architecture:        cfg.Architecture,
		OS:                  cfg.OS,
		ManifestAnnotations: manifestAnnotations,
		IndexAnnotations:    indexAnnotations,
	}

	if !cfg.Created.Time.IsZero() {
		t := cfg.Created.Time
		meta.Created = &t
	}

	labels := cfg.Config.Labels
	if len(labels) > 0 {
		meta.Labels = labels
	}

	meta.ImageVersion = extractField("org.opencontainers.image.version", manifestAnnotations, labels, indexAnnotations)
	meta.SourceURL = extractField("org.opencontainers.image.source", manifestAnnotations, labels, indexAnnotations)
	meta.Revision = extractField("org.opencontainers.image.revision", manifestAnnotations, labels, indexAnnotations)
	meta.Authors = extractField("org.opencontainers.image.authors", manifestAnnotations, labels, indexAnnotations)
	meta.Description = extractField("org.opencontainers.image.description", manifestAnnotations, labels, indexAnnotations)
	meta.BaseName = extractField("org.opencontainers.image.base.name", manifestAnnotations, labels, indexAnnotations)
	meta.URL = extractField("org.opencontainers.image.url", manifestAnnotations, labels, indexAnnotations)
	meta.Documentation = extractField("org.opencontainers.image.documentation", manifestAnnotations, labels, indexAnnotations)
	meta.Vendor = extractField("org.opencontainers.image.vendor", manifestAnnotations, labels, indexAnnotations)
	meta.Licenses = extractField("org.opencontainers.image.licenses", manifestAnnotations, labels, indexAnnotations)
	meta.Title = extractField("org.opencontainers.image.title", manifestAnnotations, labels, indexAnnotations)
	meta.BaseDigest = extractField("org.opencontainers.image.base.digest", manifestAnnotations, labels, indexAnnotations)

	return meta
}
