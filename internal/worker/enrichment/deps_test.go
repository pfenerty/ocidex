package enrichmentworker

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

type fakeEnrichmentGetter struct {
	mu       sync.Mutex
	statuses map[string]string
}

func (f *fakeEnrichmentGetter) GetEnrichment(_ context.Context, arg repository.GetEnrichmentParams) (repository.Enrichment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status, ok := f.statuses[uuidToHex(arg.SbomID)+":"+arg.EnricherName]
	if !ok {
		return repository.Enrichment{}, pgx.ErrNoRows
	}
	return repository.Enrichment{Status: status}, nil
}

type fakeEnqueuer struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, _ pgtype.UUID, _, _, enricherName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, enricherName)
	return nil
}

func (f *fakeEnqueuer) enqueued() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

type fakeHintPublisher struct {
	mu    sync.Mutex
	count int
}

func (f *fakeHintPublisher) PublishMsgAsync(_ *nats.Msg, _ ...jetstream.PublishOpt) (jetstream.PubAckFuture, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	return nil, nil
}

func (f *fakeHintPublisher) publishCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

func testSBOMID() pgtype.UUID {
	var u pgtype.UUID
	_ = u.Scan("11111111-2222-3333-4444-555555555555")
	return u
}

func TestEnqueueDependents(t *testing.T) {
	sbomID := testSBOMID()
	key := uuidToHex(sbomID) + ":oci-metadata"

	tests := []struct {
		name              string
		completedEnricher string
		statuses          map[string]string
		wantEnqueued      []string
		wantHints         int
	}{
		{
			name:              "prerequisite succeeded enqueues dependent and publishes hint",
			completedEnricher: "oci-metadata",
			statuses:          map[string]string{key: "success"},
			wantEnqueued:      []string{"git"},
			wantHints:         1,
		},
		{
			name:              "missing prerequisite row does not enqueue",
			completedEnricher: "oci-metadata",
			statuses:          map[string]string{},
			wantEnqueued:      []string{},
			wantHints:         0,
		},
		{
			name:              "non-success prerequisite status does not enqueue",
			completedEnricher: "oci-metadata",
			statuses:          map[string]string{key: "running"},
			wantEnqueued:      []string{},
			wantHints:         0,
		},
		{
			name:              "completed enricher has no dependents is a no-op",
			completedEnricher: "user",
			statuses:          map[string]string{},
			wantEnqueued:      []string{},
			wantHints:         0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			store := &fakeEnrichmentGetter{statuses: tt.statuses}
			jobSvc := &fakeEnqueuer{}
			js := &fakeHintPublisher{}
			logger := slog.New(slog.NewTextHandler(&discardWriter{}, nil))

			enqueueDependents(context.Background(), store, jobSvc, js, "ocidex",
				sbomID, "amd64", "2026-07-12", tt.completedEnricher, logger)

			is.Equal(jobSvc.enqueued(), tt.wantEnqueued)
			is.Equal(js.publishCount(), tt.wantHints)
		})
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
