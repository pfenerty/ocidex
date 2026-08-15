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

// Media types identifying an artifact attached to an image (cosign signature,
// DSSE/in-toto attestation, sigstore bundle) rather than an image itself. These
// manifests are ordinary OCI image manifests, so manifest-kind dispatch alone
// cannot tell them apart — the config, artifactType, or layer media type does.
// Mirrors the unexported set in internal/enrichment/provenance/provenance.go;
// duplicated rather than shared because importing internal/enrichment from
// internal/scanner would invert the dependency direction.
const (
	mediaTypeCosignSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
	mediaTypeDSSEEnvelope        = "application/vnd.dsse.envelope.v1+json"
)

// attachedArtifactPrefixes covers the versioned cosign/sigstore/in-toto media
// type families, e.g. application/vnd.dev.cosign.artifact.sig.v1+json.
var attachedArtifactPrefixes = []string{
	"application/vnd.dev.cosign.",
	"application/vnd.dev.sigstore.",
	"application/vnd.in-toto",
}

// URL schemes for registry endpoints.
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)
