package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/jobqueue"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

// Compile-time assertion: fakeSBOMSvc must satisfy service.SBOMService.
var _ service.SBOMService = (*fakeSBOMSvc)(nil)

// fakeScanner implements scanner.Scanner, returning minimal valid CycloneDX JSON.
type fakeScanner struct{ err error }

func (f *fakeScanner) Scan(_ context.Context, _ scanner.ScanRequest) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":[]}`), nil
}

// fakeSBOMSvc implements service.SBOMService for dispatcher tests.
type fakeSBOMSvc struct{ ingestErr error }

func (f *fakeSBOMSvc) Ingest(_ context.Context, _ *cdx.BOM, _ []byte, _ service.IngestParams) (pgtype.UUID, error) {
	if f.ingestErr != nil {
		return pgtype.UUID{}, f.ingestErr
	}
	return pgtype.UUID{Bytes: [16]byte{1}, Valid: true}, nil
}

func (f *fakeSBOMSvc) DeleteSBOM(_ context.Context, _ pgtype.UUID) error     { return nil }
func (f *fakeSBOMSvc) DeleteArtifact(_ context.Context, _ pgtype.UUID) error { return nil }
func (f *fakeSBOMSvc) ListDigestsBySource(_ context.Context, _ string) (map[string]bool, error) {
	return nil, nil
}
func (f *fakeSBOMSvc) GetSBOMNamespaceID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
	return pgtype.UUID{}, nil
}
func (f *fakeSBOMSvc) GetArtifactNamespaceID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
	return pgtype.UUID{}, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestDispatcher_ProcessOne(t *testing.T) {
	tests := []struct {
		name      string
		scanErr   error
		ingestErr error
		wantErr   bool
	}{
		{name: "success returns sbom id"},
		{name: "scan error propagates", scanErr: errors.New("boom"), wantErr: true},
		{name: "ingest error propagates", ingestErr: errors.New("nope"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			d := NewDispatcher(
				&fakeScanner{err: tt.scanErr},
				&fakeSBOMSvc{ingestErr: tt.ingestErr},
				0, // size check disabled: these cases cover scan/ingest errors
				discardLogger(),
			)

			req := scanner.ScanRequest{Repository: "testrepo", Digest: "sha256:abc"}
			sbomID, err := d.ProcessOne(context.Background(), req)

			if tt.wantErr {
				is.True(err != nil)
				is.True(!sbomID.Valid)
			} else {
				is.NoErr(err)
				is.True(sbomID.Valid)
			}
		})
	}
}

// TestDispatcher_ProcessOne_SizeGate covers the manifest size gate that keeps an
// oversized image from reaching syft. quay.io/cilium/cilium-envoy (one 1.05GB
// layer) OOMKilled the worker on every attempt, which writes no error to the
// row at all, so the stuck sweep requeued it forever.
func TestDispatcher_ProcessOne_SizeGate(t *testing.T) {
	const oneGB = 1 << 30

	tests := []struct {
		name string
		// layerSizes is what the fake registry's manifest advertises; nil
		// serves no manifest at all, standing in for an unreachable registry.
		layerSizes    []int64
		maxImageBytes int64
		wantRejected  bool
		wantScanned   bool
	}{
		{
			name:          "oversized image is rejected before scanning",
			layerSizes:    []int64{oneGB},
			maxImageBytes: 512 << 20,
			wantRejected:  true,
		},
		{
			name:          "image within the ceiling is scanned",
			layerSizes:    []int64{100 << 20},
			maxImageBytes: 512 << 20,
			wantScanned:   true,
		},
		{
			name:          "exactly at the ceiling is scanned",
			layerSizes:    []int64{512 << 20},
			maxImageBytes: 512 << 20,
			wantScanned:   true,
		},
		{
			name:          "zero ceiling disables the gate",
			layerSizes:    []int64{oneGB},
			maxImageBytes: 0,
			wantScanned:   true,
		},
		{
			// A registry that will not answer must not turn into a permanent
			// failure -- unknown size means scan and let syft report.
			name:          "unknown size falls through to the scan",
			layerSizes:    nil,
			maxImageBytes: 512 << 20,
			wantScanned:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.layerSizes == nil || !strings.Contains(r.URL.Path, "/manifests/") {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				layers := make([]map[string]any, 0, len(tt.layerSizes))
				for _, sz := range tt.layerSizes {
					layers = append(layers, map[string]any{
						"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
						"size":      sz,
					})
				}
				w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"mediaType": "application/vnd.oci.image.manifest.v1+json",
					"layers":    layers,
				})
			}))
			defer srv.Close()

			sc := &countingScanner{}
			d := NewDispatcher(sc, &fakeSBOMSvc{}, tt.maxImageBytes, discardLogger())

			_, err := d.ProcessOne(context.Background(), scanner.ScanRequest{
				RegistryURL: strings.TrimPrefix(srv.URL, "http://"),
				Insecure:    true,
				Repository:  "cilium/cilium-envoy",
				Digest:      "sha256:abc",
				// Pre-populated so FillMetadata short-circuits and the only
				// registry read under test is the size probe.
				Architecture: "amd64",
				BuildDate:    "2026-01-01T00:00:00Z",
				ImageVersion: "1.0.0",
			})

			if tt.wantRejected {
				is.True(err != nil)                            // oversized image must fail
				is.True(errors.Is(err, jobqueue.ErrPermanent)) // and never be retried
				is.Equal(sc.calls, 0)                          // syft must not have been reached
				return
			}
			is.NoErr(err)
			is.Equal(sc.calls, 1)
		})
	}
}

// countingScanner records how many times the scan was actually attempted.
type countingScanner struct{ calls int }

func (c *countingScanner) Scan(_ context.Context, _ scanner.ScanRequest) ([]byte, error) {
	c.calls++
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":[]}`), nil
}
