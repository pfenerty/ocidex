package engine

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/netguard"
	"github.com/pfenerty/ocidex/internal/scanner"
)

// TestScanEgressDenied covers ocidex-avsz.7: with the default transport guarded,
// a syft pull from a registry on loopback is refused before it connects, and the
// failure is classified permanent. It is the canary for stereoscope still
// building its transport from http.DefaultTransport.
func TestScanEgressDenied(t *testing.T) {
	is := is.New(t)
	dt := http.DefaultTransport.(*http.Transport)
	orig := dt.DialContext
	t.Cleanup(func() { dt.DialContext = orig })
	GuardDefaultTransport(netguard.Policy{})

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	sc := NewSyftScanner(slog.New(slog.DiscardHandler), "none")
	_, err := sc.Scan(t.Context(), scanner.ScanRequest{
		RegistryURL: strings.TrimPrefix(srv.URL, "http://"),
		Insecure:    true,
		Repository:  "repo",
		Digest:      "sha256:" + strings.Repeat("a", 64),
	})

	is.True(err != nil)
	is.Equal(hits, 0)
	t.Logf("denied scan error: %v (errors.Is ErrDenied: %v)", err, errors.Is(err, netguard.ErrDenied))
	is.True(isPermanentScanError(err))
}
