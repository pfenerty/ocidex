package scanner

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// fakeJobSvc implements service.JobService for dispatcher tests.
type fakeJobSvc struct {
	mu         sync.Mutex
	startCalls int
	startErr   error
	finishErr  error
	failErr    error
}

func (f *fakeJobSvc) Enqueue(_ context.Context, _, _, _, _, _ string) (service.ScanJob, error) {
	return service.ScanJob{}, nil
}

func (f *fakeJobSvc) Start(_ context.Context, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls++
	return f.startErr
}

func (f *fakeJobSvc) Finish(_ context.Context, _ string, _ pgtype.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.finishErr
}

func (f *fakeJobSvc) Fail(_ context.Context, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.failErr
}

func (f *fakeJobSvc) List(_ context.Context, _ string, _, _ int32) ([]service.ScanJob, int64, error) {
	return nil, 0, nil
}

func (f *fakeJobSvc) Get(_ context.Context, _ string) (service.ScanJob, error) {
	return service.ScanJob{}, nil
}

func (f *fakeJobSvc) CountByState(_ context.Context) (int64, int64, int64, int64, error) {
	return 0, 0, 0, 0, nil
}

func (f *fakeJobSvc) getStartCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startCalls
}

// fakeScanner implements Scanner, returning minimal valid CycloneDX JSON.
type fakeScanner struct{ err error }

func (f *fakeScanner) Scan(_ context.Context, _ ScanRequest) ([]byte, error) {
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

func (f *fakeSBOMSvc) DeleteSBOM(_ context.Context, _ pgtype.UUID) error        { return nil }
func (f *fakeSBOMSvc) DeleteArtifact(_ context.Context, _ pgtype.UUID) error    { return nil }
func (f *fakeSBOMSvc) ListDigestsByRegistry(_ context.Context, _ string) (map[string]bool, error) {
	return nil, nil
}

func TestDispatcher_JobTracking(t *testing.T) {
	tests := []struct {
		name           string
		useWorkerPath  bool
		finishErr      error
		wantStartCalls int
		wantErr        bool
	}{
		{
			name:           "ProcessOne does not call Start (NATS extension owns it)",
			useWorkerPath:  false,
			wantStartCalls: 0,
			wantErr:        false,
		},
		{
			name:           "worker calls Start exactly once per job",
			useWorkerPath:  true,
			wantStartCalls: 1,
			wantErr:        false,
		},
		{
			name:           "ProcessOne returns error when finishJob fails",
			useWorkerPath:  false,
			finishErr:      errors.New("db write failed"),
			wantStartCalls: 0,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			jobSvc := &fakeJobSvc{finishErr: tt.finishErr}
			sc := &fakeScanner{}
			sbomSvc := &fakeSBOMSvc{}

			d := NewDispatcher(sc, sbomSvc, 1, 10, discardLogger(), jobSvc)

			req := ScanRequest{
				MsgID:      "msg-test-id",
				Repository: "testrepo",
				Digest:     "sha256:abc123",
			}

			if tt.useWorkerPath {
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() {
					defer close(done)
					d.Run(ctx)
				}()
				err := d.Submit(ctx, req)
				is.NoErr(err)
				time.Sleep(100 * time.Millisecond)
				cancel()
				<-done
				is.Equal(jobSvc.getStartCalls(), tt.wantStartCalls)
			} else {
				err := d.ProcessOne(context.Background(), req)
				is.Equal(jobSvc.getStartCalls(), tt.wantStartCalls)
				if tt.wantErr {
					is.True(err != nil)
				} else {
					is.NoErr(err)
				}
			}
		})
	}
}
