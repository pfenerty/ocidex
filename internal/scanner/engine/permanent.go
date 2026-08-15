package engine

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// permanentScanErrorSubstrings identify scan failures that will recur
// identically on every retry. Substring matching is a deliberate last resort:
// syft returns these as plain fmt.Errorf values with no exported error type to
// match on, so there is nothing for errors.As to target.
//
//   - "unsupported layer media type" — the image's layers are not a filesystem
//     syft can catalog (cosign signature payloads, arbitrary OCI artifacts).
//   - "MANIFEST_UNKNOWN" — the registry's error code for a manifest that no
//     longer exists; a string fallback for the 404 case below, since it is not
//     confirmed that stereoscope preserves *transport.Error through its wrapping.
var permanentScanErrorSubstrings = []string{
	"unsupported layer media type",
	"MANIFEST_UNKNOWN",
}

// isPermanentScanError reports whether a scan failure is worth retrying. A 404
// means the image was deleted between the catalog walk and the scan; any other
// registry status (auth, 5xx) and every network or timeout error stays
// retryable. Mirrors the classification at
// internal/enrichment/provenance/provenance.go artifactMissing.
func isPermanentScanError(err error) bool {
	if err == nil {
		return false
	}
	var terr *transport.Error
	if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
		return true
	}
	msg := err.Error()
	for _, s := range permanentScanErrorSubstrings {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
