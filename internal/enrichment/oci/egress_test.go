package oci

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/netguard"
)

// TestEnrichEgressDenied covers ocidex-avsz.7: an artifact name on a refused
// address is never dialed.
func TestEnrichEgressDenied(t *testing.T) {
	is := is.New(t)
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	e := NewEnricher(WithInsecure(), WithEgress(netguard.Policy{}))
	_, err := e.Enrich(t.Context(), enrichment.SubjectRef{
		ArtifactName: host + "/repo",
		Digest:       "sha256:" + strings.Repeat("a", 64),
	})

	is.True(errors.Is(err, netguard.ErrDenied))
	is.Equal(hits, 0)
}
