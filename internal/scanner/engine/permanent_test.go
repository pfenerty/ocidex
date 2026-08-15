package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/matryer/is"
)

// transportErr builds a *transport.Error the way go-containerregistry surfaces
// a registry status response, so the errors.As branch is exercised against the
// real type rather than a stand-in.
func transportErr(status int, code transport.ErrorCode) *transport.Error {
	return &transport.Error{
		StatusCode: status,
		Errors:     []transport.Diagnostic{{Code: code, Message: "manifest unknown"}},
	}
}

// TestIsPermanentScanError pins which scan failures skip the retry budget.
// Getting a negative wrong is the costly direction: a transient registry blip
// classified as permanent silently drops a scannable image (ocidex-9eu4).
func TestIsPermanentScanError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			"syft unsupported layer media type",
			errors.New("failed to construct source from user input: oci-registry: unsupported layer media type(s): layer 0: application/vnd.dev.cosign.simplesigning.v1+json"),
			true,
		},
		{
			"unsupported media type wrapped",
			fmt.Errorf("scan: %w", errors.New("unsupported layer media type: application/vnd.dsse.envelope.v1+json")),
			true,
		},
		{
			"transport 404",
			fmt.Errorf("scan: %w", transportErr(http.StatusNotFound, transport.ManifestUnknownErrorCode)),
			true,
		},
		{
			"MANIFEST_UNKNOWN string only",
			errors.New(`GET https://ghcr.io/v2/x/manifests/sha256:abc: MANIFEST_UNKNOWN: manifest unknown`),
			true,
		},
		// Negatives — every one of these must stay retryable.
		{"transport 401", transportErr(http.StatusUnauthorized, transport.UnauthorizedErrorCode), false},
		{"transport 429", transportErr(http.StatusTooManyRequests, transport.TooManyRequestsErrorCode), false},
		{"transport 500", transportErr(http.StatusInternalServerError, transport.UnsupportedErrorCode), false},
		{"connection refused", errors.New("dial tcp 10.0.0.1:443: connect: connection refused"), false},
		{"deadline exceeded", fmt.Errorf("scan: %w", context.DeadlineExceeded), false},
		{"canceled", fmt.Errorf("scan: %w", context.Canceled), false},
		{"generic failure", errors.New("scan: failed to create SBOM"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(isPermanentScanError(tc.err), tc.want)
		})
	}
}
