package api_test

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

const scanRegistryID = "0f0e0d0c-0b0a-0908-0706-050403020100"

func scanRegistryRouter(t *testing.T, walks *scanner.AdhocWalks) http.Handler {
	t.Helper()
	regSvc := &fakeRegistryService{registry: service.Registry{
		ID: scanRegistryID, Name: "r", NamespaceID: testNamespaceID,
		// Nothing listens here, so a walk the test lets run fails fast.
		URL: "127.0.0.1:1", Type: "generic",
	}}
	h := api.NewHandler(nil, nil, createRegistryAuthService(), regSvc, nil, nil, nil, nil, nil, nil,
		&fakePinger{}, &recordingScanSubmitter{}, &config.Config{})
	if walks != nil {
		h = h.WithAdhocWalks(walks)
	}
	return api.NewRouter(h, "*", "", "")
}

func startedAdhocWalks(t *testing.T) *scanner.AdhocWalks {
	t.Helper()
	w := scanner.NewAdhocWalks(2, time.Minute, slog.Default())
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Stop() })
	return w
}

// A scan request for a registry whose walk is already queued or running gets
// 409 instead of starting a second walk (ocidex-89c9.2).
func TestScanRegistryDedupe(t *testing.T) {
	is := is.New(t)
	walks := startedAdhocWalks(t)
	release := make(chan struct{})
	defer close(release)
	is.NoErr(walks.Run(scanRegistryID, func(context.Context) { <-release }))

	w := memberRequest(scanRegistryRouter(t, walks), http.MethodPost,
		"/api/v1/registries/"+scanRegistryID+"/scan", "", "owner-token")
	is.Equal(w.Code, http.StatusConflict)
}

func TestScanRegistryAccepted(t *testing.T) {
	is := is.New(t)
	// force skips the known-digest lookup, which this router has no SBOM
	// service for.
	w := memberRequest(scanRegistryRouter(t, startedAdhocWalks(t)), http.MethodPost,
		"/api/v1/registries/"+scanRegistryID+"/scan?force=true", "", "owner-token")
	is.Equal(w.Code, http.StatusAccepted)
}

// Outside Start and Stop (shutting down) the route answers 503, and without a
// coordinator it answers as if the scanner were off.
func TestScanRegistryUnavailable(t *testing.T) {
	tests := []struct {
		name  string
		walks *scanner.AdhocWalks
	}{
		{"not started", scanner.NewAdhocWalks(1, time.Minute, slog.Default())},
		{"no coordinator", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			w := memberRequest(scanRegistryRouter(t, tt.walks), http.MethodPost,
				"/api/v1/registries/"+scanRegistryID+"/scan", "", "owner-token")
			is.Equal(w.Code, http.StatusServiceUnavailable)
		})
	}
}
