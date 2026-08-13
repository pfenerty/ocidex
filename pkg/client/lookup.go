package client

import (
	"context"
	"net/http"
	"net/url"
)

// LookupArtifact resolves an ADR-042 name-keyed artifact query to the same body
// GetArtifact returns. Narrow an ambiguous query by setting Type, then Group:
// a query matching more than one visible artifact fails with a *ConflictError
// carrying the candidates.
func (c *httpClient) LookupArtifact(ctx context.Context, params LookupArtifactParams) (ArtifactDetail, error) {
	p := url.Values{"name": {params.Name}}
	setOptional(p, "type", params.Type)
	setOptional(p, "group", params.Group)

	var out ArtifactDetail
	err := c.request(ctx, http.MethodGet, "/api/v1/artifacts/lookup", p, nil, &out)
	return out, err
}

// LookupSBOM resolves an ADR-042 name-keyed SBOM query to the same body GetSBOM
// returns. Supply either Digest on its own, or Artifact and Version narrowed
// with Arch then Flavor; the digest form is unique by construction and so never
// yields a *ConflictError.
func (c *httpClient) LookupSBOM(ctx context.Context, params LookupSbomParams) (SBOMDetail, error) {
	p := url.Values{}
	setOptional(p, "artifact", params.Artifact)
	setOptional(p, "version", params.Version)
	setOptional(p, "arch", params.Arch)
	setOptional(p, "flavor", params.Flavor)
	setOptional(p, "digest", params.Digest)
	setOptional(p, "include", params.Include)

	var out SBOMDetail
	err := c.request(ctx, http.MethodGet, "/api/v1/sboms/lookup", p, nil, &out)
	return out, err
}

// LookupLicense resolves an SPDX identifier to its license record. spdx_id is a
// natural key, so this never yields a *ConflictError — only the license or
// ErrNotFound.
func (c *httpClient) LookupLicense(ctx context.Context, spdxID string) (LicenseCount, error) {
	var out LicenseCount
	err := c.request(ctx, http.MethodGet, "/api/v1/licenses/lookup", url.Values{"spdxId": {spdxID}}, nil, &out)
	return out, err
}

// setOptional sets a query parameter only when the caller supplied a non-empty
// value. The server treats an empty qualifier as a wildcard, so sending one
// would be harmless but noisy.
func setOptional(p url.Values, name string, v *string) {
	if v != nil && *v != "" {
		p.Set(name, *v)
	}
}
