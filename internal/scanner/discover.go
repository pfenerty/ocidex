package scanner

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pfenerty/ocidex/internal/service"
)

// DiscoveredManifest represents a single manifest found by a registry-specific discoverer.
type DiscoveredManifest struct {
	Digest    string // e.g. "sha256:abc123..."
	MediaType string // e.g. "application/vnd.oci.image.manifest.v1+json"
	Tag       string // empty for untagged manifests
	Arch      string // may be empty; caller resolves via ociGetImageMetadata
}

// ManifestDiscoverer lists all manifests (tagged and untagged) for a given repository.
type ManifestDiscoverer interface {
	DiscoverManifests(ctx context.Context, client *http.Client, baseURL, repo string) ([]DiscoveredManifest, error)
}

// discovererFactories maps registry type strings to constructor functions.
// Populated via RegisterDiscoverer calls in each per-type file's init().
var discovererFactories = map[string]func(service.Registry) ManifestDiscoverer{}

// RegisterDiscoverer registers a factory for the given registry type name.
func RegisterDiscoverer(typeName string, fn func(service.Registry) ManifestDiscoverer) {
	discovererFactories[typeName] = fn
}

// discovererForType returns a ManifestDiscoverer for the registry type,
// or an unknownDiscoverer that returns an explicit error for unregistered types.
func discovererForType(reg service.Registry) ManifestDiscoverer {
	fn, ok := discovererFactories[reg.Type]
	if !ok {
		return &unknownDiscoverer{typeName: reg.Type}
	}
	return fn(reg)
}

// unknownDiscoverer is returned for registry types with no registered factory.
type unknownDiscoverer struct {
	typeName string
}

func (u *unknownDiscoverer) DiscoverManifests(_ context.Context, _ *http.Client, _, _ string) ([]DiscoveredManifest, error) {
	return nil, fmt.Errorf("unsupported registry type %q: no manifest discoverer registered", u.typeName)
}

// isImageManifestType returns true for OCI/Docker image manifest media types.
func isImageManifestType(mt string) bool {
	switch mt {
	case "application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json":
		return true
	}
	return false
}
