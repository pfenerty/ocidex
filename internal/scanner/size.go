package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// ImageLayerBytes reports the total compressed layer size req's image
// advertises in its manifest.
//
// The second return is false when the size could not be determined — the
// registry was unreachable, the manifest did not parse, or it carried no
// descriptor sizes. Callers must treat that as "unknown" and let the scan
// proceed: refusing to scan an image because its registry was briefly down
// would turn a transient fault into a permanent failure.
//
// This reads only the manifest, never a blob, so it costs one small GET
// against a scan that would otherwise pull gigabytes.
func ImageLayerBytes(ctx context.Context, req ScanRequest) (int64, bool) {
	scheme := schemeHTTPS
	if req.Insecure {
		scheme = schemeHTTP
	}
	baseURL := scheme + "://" + normalizeRegistryHost(req.RegistryURL)
	client := &http.Client{Transport: newOCITokenTransport(req.AuthUsername, req.AuthToken)}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		baseURL+"/v2/"+req.Repository+"/manifests/"+req.Digest, nil)
	if err != nil {
		return 0, false
	}
	httpReq.Header.Set("Accept", strings.Join([]string{
		mediaTypeOCIManifest,
		mediaTypeDockerManifest,
	}, ","))

	resp, err := client.Do(httpReq) //nolint:gosec
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false
	}

	var manifest ociManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return 0, false
	}
	total := manifest.totalLayerBytes()
	if total <= 0 {
		return 0, false
	}
	return total, true
}
