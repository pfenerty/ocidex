package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

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
func (f *fakeSBOMSvc) ListDigestsByRegistry(_ context.Context, _ string) (map[string]bool, error) {
	return nil, nil
}
func (f *fakeSBOMSvc) GetSBOMRegistryID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
	return pgtype.UUID{}, nil
}
func (f *fakeSBOMSvc) GetArtifactOwnerID(_ context.Context, _ pgtype.UUID) (pgtype.UUID, error) {
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
