package enrichment

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// fakeRecheckStore records ListSBOMsDueForProvenanceRecheck and
// RequeueSucceededEnrichmentJob calls.
type fakeRecheckStore struct {
	due           []pgtype.UUID
	listErr       error
	requeueRows   int64
	requeueErr    error
	requeuedSBOMs []pgtype.UUID
	listCallCount int
	listArgs      []repository.ListSBOMsDueForProvenanceRecheckParams
	mu            sync.Mutex
}

func (s *fakeRecheckStore) ListSBOMsDueForProvenanceRecheck(_ context.Context, arg repository.ListSBOMsDueForProvenanceRecheckParams) ([]pgtype.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listCallCount++
	s.listArgs = append(s.listArgs, arg)
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.due, nil
}

func (s *fakeRecheckStore) RequeueSucceededEnrichmentJob(_ context.Context, arg repository.RequeueSucceededEnrichmentJobParams) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.requeueErr != nil {
		return 0, s.requeueErr
	}
	if arg.EnricherName != "provenance" {
		return 0, nil
	}
	s.requeuedSBOMs = append(s.requeuedSBOMs, arg.SbomID)
	return s.requeueRows, nil
}

func TestReverifier_Tick_RequeuesDueSBOMs(t *testing.T) {
	sbom1 := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	sbom2 := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	store := &fakeRecheckStore{due: []pgtype.UUID{sbom1, sbom2}, requeueRows: 1}
	r := NewReverifier(store, 24*time.Hour, nil)

	r.tick(context.Background())

	if len(store.requeuedSBOMs) != 2 {
		t.Fatalf("expected 2 requeue calls, got %d", len(store.requeuedSBOMs))
	}
	if store.requeuedSBOMs[0] != sbom1 || store.requeuedSBOMs[1] != sbom2 {
		t.Errorf("expected requeues for sbom1 then sbom2, got %v", store.requeuedSBOMs)
	}
}

func TestReverifier_Tick_NoDueSBOMs(t *testing.T) {
	store := &fakeRecheckStore{due: nil}
	r := NewReverifier(store, 24*time.Hour, nil)

	r.tick(context.Background())

	if len(store.requeuedSBOMs) != 0 {
		t.Errorf("expected no requeue calls when nothing is due, got %d", len(store.requeuedSBOMs))
	}
}

func TestReverifier_Tick_ListErrorDoesNotPanic(t *testing.T) {
	store := &fakeRecheckStore{listErr: context.DeadlineExceeded}
	r := NewReverifier(store, 24*time.Hour, nil)

	r.tick(context.Background()) // must not panic; error is logged and swallowed

	if len(store.requeuedSBOMs) != 0 {
		t.Errorf("expected no requeue calls when listing fails, got %d", len(store.requeuedSBOMs))
	}
}

func TestReverifier_Tick_ContinuesAfterOneRequeueError(t *testing.T) {
	sbom1 := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	sbom2 := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	store := &fakeRecheckStore{due: []pgtype.UUID{sbom1, sbom2}, requeueErr: context.DeadlineExceeded}
	r := NewReverifier(store, 24*time.Hour, nil)

	r.tick(context.Background()) // must not stop at the first error

	if store.listCallCount != 1 {
		t.Errorf("expected exactly 1 list call, got %d", store.listCallCount)
	}
}

func (s *fakeRecheckStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listCallCount
}

func (s *fakeRecheckStore) lastListArg() repository.ListSBOMsDueForProvenanceRecheckParams {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listArgs[len(s.listArgs)-1]
}

func TestReverifier_Tick_UsesBatchSizeAndIntervalCutoff(t *testing.T) {
	store := &fakeRecheckStore{}
	interval := 6 * time.Hour
	r := NewReverifier(store, interval, nil)

	before := time.Now().Add(-interval)
	r.tick(context.Background())
	after := time.Now().Add(-interval)

	arg := store.lastListArg()
	if arg.RowLimit != recheckBatchSize {
		t.Errorf("expected RowLimit %d, got %d", recheckBatchSize, arg.RowLimit)
	}
	if arg.Cutoff.Time.Before(before) || arg.Cutoff.Time.After(after) {
		t.Errorf("expected cutoff within [%v, %v], got %v", before, after, arg.Cutoff.Time)
	}
	if !arg.Cutoff.Valid {
		t.Error("expected cutoff timestamp to be valid")
	}
}

func TestReverifier_Run_TicksImmediatelyOnStart(t *testing.T) {
	store := &fakeRecheckStore{}
	r := NewReverifier(store, time.Hour, nil) // long interval: only the immediate tick can fire

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	<-done

	if got := store.callCount(); got < 1 {
		t.Errorf("expected at least 1 immediate tick, got %d", got)
	}
}

func TestReverifier_Run_TicksAtConfiguredInterval(t *testing.T) {
	store := &fakeRecheckStore{}
	r := NewReverifier(store, 15*time.Millisecond, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	<-done

	// immediate tick + at least 2 ticker fires over 60ms at a 15ms interval
	if got := store.callCount(); got < 3 {
		t.Errorf("expected ticker period to track the configured interval, got %d ticks in 60ms at 15ms interval", got)
	}
}
