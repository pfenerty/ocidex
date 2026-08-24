package enrichment

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeRecheckStore records ListSBOMsDueForProvenanceRecheck and
// RequeueEnrichmentJobForRecheck calls.
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

func (s *fakeRecheckStore) RequeueEnrichmentJobForRecheck(_ context.Context, arg repository.RequeueEnrichmentJobForRecheckParams) (int64, error) {
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

// drainingRecheckStore models a finite corpus of due SBOMs: each list call
// returns up to RowLimit of what's left, so repeated ticks drain it.
type drainingRecheckStore struct {
	mu        sync.Mutex
	remaining int
	requeued  int
}

func (s *drainingRecheckStore) ListSBOMsDueForProvenanceRecheck(_ context.Context, arg repository.ListSBOMsDueForProvenanceRecheckParams) ([]pgtype.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := int(arg.RowLimit)
	if n > s.remaining {
		n = s.remaining
	}
	out := make([]pgtype.UUID, n)
	for i := range out {
		out[i] = pgtype.UUID{Bytes: [16]byte{byte(i)}, Valid: true}
	}
	s.remaining -= n
	return out, nil
}

func (s *drainingRecheckStore) RequeueEnrichmentJobForRecheck(_ context.Context, _ repository.RequeueEnrichmentJobForRecheckParams) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requeued++
	return 1, nil
}

// A corpus larger than recheckBatchSize must still be swept in full within one
// recheck interval. Regression test for the batch cap silently stretching
// PROVENANCE_RECHECK_INTERVAL into a multi-day sweep: when the ticker ran once
// per interval, only recheckBatchSize SBOMs could ever be rechecked per
// interval, so a corpus of 3764 took ~8 days at a nominal 24h setting.
func TestReverifier_SweepsWholeCorpusWithinOneInterval(t *testing.T) {
	const corpus = 3764 // the ocidex-dev provenance corpus that exposed this
	store := &drainingRecheckStore{remaining: corpus}
	interval := 24 * time.Hour
	r := NewReverifier(store, interval, discardLogger())

	if r.sweepInterval > interval {
		t.Fatalf("sweep interval %v must not exceed recheck interval %v", r.sweepInterval, interval)
	}
	sweeps := int(interval / r.sweepInterval)
	for range sweeps {
		r.tick(context.Background())
	}

	if store.remaining != 0 {
		t.Errorf("expected corpus of %d fully swept in %d sweeps over one %v interval, %d left",
			corpus, sweeps, interval, store.remaining)
	}
	if store.requeued != corpus {
		t.Errorf("expected %d requeues, got %d", corpus, store.requeued)
	}
}

// The staleness cutoff is the user-facing meaning of the interval, so it must
// keep tracking interval even though the ticker now runs on sweepInterval.
func TestReverifier_Tick_CutoffUsesIntervalNotSweepInterval(t *testing.T) {
	store := &fakeRecheckStore{}
	interval := 24 * time.Hour
	r := NewReverifier(store, interval, discardLogger())

	if r.sweepInterval >= interval {
		t.Fatalf("expected sweep interval to be shorter than %v, got %v", interval, r.sweepInterval)
	}

	before := time.Now().Add(-interval)
	r.tick(context.Background())
	after := time.Now().Add(-interval)

	cutoff := store.lastListArg().Cutoff.Time
	if cutoff.Before(before) || cutoff.After(after) {
		t.Errorf("expected cutoff within [%v, %v] (derived from interval), got %v", before, after, cutoff)
	}
}

func TestReverifier_Tick_WarnsWhenBatchIsFull(t *testing.T) {
	full := make([]pgtype.UUID, recheckBatchSize)
	for i := range full {
		full[i] = pgtype.UUID{Bytes: [16]byte{byte(i)}, Valid: true}
	}

	tests := []struct {
		name     string
		due      []pgtype.UUID
		wantWarn bool
	}{
		{name: "full batch warns", due: full, wantWarn: true},
		{name: "partial batch is quiet", due: full[:recheckBatchSize-1], wantWarn: false},
		{name: "nothing due is quiet", due: nil, wantWarn: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			store := &fakeRecheckStore{due: tt.due, requeueRows: 1}
			r := NewReverifier(store, 24*time.Hour, logger)

			r.tick(context.Background())

			gotWarn := strings.Contains(buf.String(), "falling behind")
			if gotWarn != tt.wantWarn {
				t.Errorf("warn fired = %v, want %v (log: %q)", gotWarn, tt.wantWarn, buf.String())
			}
		})
	}
}

func TestDeriveSweepInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		want     time.Duration
	}{
		{name: "default 24h sweeps hourly", interval: 24 * time.Hour, want: time.Hour},
		{name: "divides evenly", interval: 48 * time.Hour, want: 2 * time.Hour},
		{name: "short interval floored at the minimum", interval: 12 * time.Minute, want: minSweepInterval},
		{name: "never sweeps less often than the interval", interval: 30 * time.Second, want: 30 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveSweepInterval(tt.interval); got != tt.want {
				t.Errorf("deriveSweepInterval(%v) = %v, want %v", tt.interval, got, tt.want)
			}
		})
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
