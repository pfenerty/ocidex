package ocivalidate

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/netguard"
)

// TestValidateDigestEgressDenied covers ocidex-avsz.7: ingest validation names
// a host from the uploaded SBOM, so it must not dial a refused one.
func TestValidateDigestEgressDenied(t *testing.T) {
	is := is.New(t)
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	v := NewValidator(WithInsecure(), WithEgress(netguard.Policy{}))
	err := v.ValidateDigest(t.Context(), host+"/repo", "sha256:"+strings.Repeat("a", 64))

	is.True(errors.Is(err, netguard.ErrDenied))
	is.Equal(hits, 0)
}
