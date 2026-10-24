package service

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/event"
)

// fakeRetention hands out a fixed backlog, batch by batch.
type fakeRetention struct {
	window, newest int64
	prunes         int
	listed         int
}

func (f *fakeRetention) Candidates(_ context.Context, _ RetentionPolicy, _ int) (RetentionCandidates, error) {
	f.listed++
	return RetentionCandidates{
		Window: make([]pgtype.UUID, f.window),
		Newest: make([]pgtype.UUID, f.newest),
	}, nil
}

func (f *fakeRetention) Prune(_ context.Context, _ RetentionPolicy, batch int) (PruneCounts, error) {
	f.prunes++
	w, n := min(f.window, int64(batch)), min(f.newest, int64(batch))
	f.window -= w
	f.newest -= n
	return PruneCounts{Window: w, Newest: n}, nil
}

func TestRetentionSweepPrunesUntilEmpty(t *testing.T) {
	is := is.New(t)
	svc := &fakeRetention{window: 120, newest: 30}
	pub := &fakePublisher{}
	s := NewRetentionSweeper(svc, RetentionPolicy{KeepLast: 20, RegistryWindow: true}, false, 0, 50, discardLogger()).
		WithPublisher(pub)
	s.pause = 0

	got, err := s.Sweep(t.Context())
	is.NoErr(err)
	is.Equal(got, PruneCounts{Window: 120, Newest: 30})
	is.Equal(svc.prunes, 4) // 50+50+20 window, then one empty batch
	is.Equal(pub.events, []event.Type{event.RetentionSwept})
}

func TestRetentionSweepDryRunDeletesNothing(t *testing.T) {
	is := is.New(t)
	svc := &fakeRetention{window: 7, newest: 3}
	s := NewRetentionSweeper(svc, RetentionPolicy{KeepLast: 20, RegistryWindow: true}, true, 0, 50, discardLogger())

	got, err := s.Sweep(t.Context())
	is.NoErr(err)
	is.Equal(got, PruneCounts{Window: 7, Newest: 3})
	is.Equal(svc.prunes, 0)
	is.Equal(svc.listed, 1)
}

func TestRetentionSweepStopsOnCancel(t *testing.T) {
	is := is.New(t)
	svc := &fakeRetention{newest: 500}
	s := NewRetentionSweeper(svc, RetentionPolicy{KeepLast: 20}, false, 0, 50, discardLogger())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	got, err := s.Sweep(ctx)
	is.True(err != nil)
	is.Equal(got.Newest, int64(50)) // one batch, then the pause sees the cancel
}
