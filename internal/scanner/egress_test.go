package scanner

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/netguard"
	"github.com/pfenerty/ocidex/internal/service"
)

// testEgress admits loopback, which is where every httptest registry listens.
var testEgress = netguard.Policy{AllowCIDRs: []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}}

// TestWalkRegistryEgress covers ocidex-avsz.6: the catalog walk dials through
// the egress policy, so a registry on loopback is refused under the default
// policy — with an error callers classify as permanent — and walked once
// loopback is allowed.
func TestWalkRegistryEgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/_catalog" {
			_, _ = w.Write([]byte(`{"repositories":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	reg := service.Registry{URL: srv.URL}

	t.Run("default policy refuses loopback", func(t *testing.T) {
		is := is.New(t)
		_, err := WalkRegistry(t.Context(), reg, &fakeSubmitter{}, nil, netguard.Policy{}, discardLogger())
		is.True(errors.Is(err, netguard.ErrDenied))
	})
	t.Run("allowed loopback is walked", func(t *testing.T) {
		is := is.New(t)
		_, err := WalkRegistry(t.Context(), reg, &fakeSubmitter{}, nil, testEgress, discardLogger())
		is.NoErr(err)
	})
}

func TestImageLayerBytesEgress(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	_, known, err := ImageLayerBytes(t.Context(), ScanRequest{RegistryURL: srv.URL, Insecure: true, Repository: "r", Digest: "sha256:x"}, netguard.Policy{})
	is.True(!known)
	is.True(errors.Is(err, netguard.ErrDenied))
}
