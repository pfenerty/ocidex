package scanner

import (
	"context"
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

// discovererForType returns a ManifestDiscoverer for the given registry type,
// or nil if the type does not support full manifest discovery.
func discovererForType(reg service.Registry) ManifestDiscoverer {
	switch reg.Type {
	case "zot":
		return &zotDiscoverer{}
	case "harbor":
		return &harborDiscoverer{
			authUsername: derefStr(reg.AuthUsername),
			authToken:    derefStr(reg.AuthToken),
		}
	case "ghcr":
		return &ghcrDiscoverer{
			authToken: derefStr(reg.AuthToken),
		}
	default:
		return nil
	}
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
