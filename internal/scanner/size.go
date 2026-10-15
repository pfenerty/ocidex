package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/pfenerty/ocidex/internal/netguard"
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
//
// A dial egress refuses is the one failure reported as an error, wrapping
// netguard.ErrDenied: unlike an outage, it will be refused again next time.
func ImageLayerBytes(ctx context.Context, req ScanRequest, egress netguard.Policy) (int64, bool, error) {
	scheme := schemeHTTPS
	if req.Insecure {
		scheme = schemeHTTP
	}
	baseURL := scheme + "://" + normalizeRegistryHost(req.RegistryURL)
	client := registryClient(egress, 0, req.AuthUsername, req.AuthToken)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		baseURL+"/v2/"+req.Repository+"/manifests/"+req.Digest, nil)
	if err != nil {
		return 0, false, nil
	}
	httpReq.Header.Set("Accept", strings.Join([]string{
		mediaTypeOCIManifest,
		mediaTypeDockerManifest,
	}, ","))

	resp, err := client.Do(httpReq) //nolint:gosec
	if errors.Is(err, netguard.ErrDenied) {
		return 0, false, err
	}
	if err != nil {
		return 0, false, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false, nil
	}

	var manifest ociManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return 0, false, nil
	}
	total := manifest.totalLayerBytes()
	if total <= 0 {
		return 0, false, nil
	}
	return total, true, nil
}
