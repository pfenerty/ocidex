package scanner

// OCI and Docker manifest media types used in registry Accept headers and in
// manifest-kind dispatch. Defined here rather than pulled from
// opencontainers/image-spec because that module carries no constants for the
// Docker distribution types, so importing it would cover only half the set.
const (
	mediaTypeOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// URL schemes for registry endpoints.
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)
