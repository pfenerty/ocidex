package vuln

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/event"
)

// blockingOSV is an OSVQuerier whose QueryPurls blocks until released,
// letting tests observe how many lookups are in flight at once.
type blockingOSV struct {
	started chan struct{}
	release chan struct{}

	mu       sync.Mutex
	current  int
	maxSeen  int
	numCalls int
}

func newBlockingOSV(buf int) *blockingOSV {
	return &blockingOSV{
		started: make(chan struct{}, buf),
		release: make(chan struct{}, buf),
	}
}

func (b *blockingOSV) QueryPurls(_ context.Context, purls []string) (map[string][]QueryRef, error) {
	b.mu.Lock()
	b.current++
	b.numCalls++
	if b.current > b.maxSeen {
		b.maxSeen = b.current
	}
	b.mu.Unlock()

	b.started <- struct{}{}
	<-b.release

	b.mu.Lock()
	b.current--
	b.mu.Unlock()

	out := make(map[string][]QueryRef, len(purls))
	for _, p := range purls {
		out[p] = nil
	}
	return out, nil
}

func (b *blockingOSV) GetVuln(_ context.Context, _ string) (*Record, error) {
	return nil, nil
}

func TestIngestVulnExtension_BoundsConcurrency(t *testing.T) {
	is := is.New(t)

	const maxConcurrency = 2
	const numEvents = 5

	store := newFakeStore()
	store.unknownForSBOM = []string{"pkg:npm/leftpad@1.0.0"}

	osv := newBlockingOSV(numEvents)
	logger := slog.Default()
	refresher := NewRefreshService(store, osv, logger)
	ext := NewIngestVulnExtension(store, refresher, logger, true, maxConcurrency)

	bus := event.NewBus(logger)
	is.NoErr(ext.Init(bus))

	for i := 0; i < numEvents; i++ {
		bus.Publish(t.Context(), event.SBOMIngested, event.SBOMIngestedData{
			SBOMID: pgtype.UUID{Bytes: [16]byte{byte(i + 1)}, Valid: true},
		})
	}

	processed := 0
	for processed < numEvents {
		batch := 0
		for batch < maxConcurrency && processed+batch < numEvents {
			select {
			case <-osv.started:
				batch++
			case <-time.After(2 * time.Second):
				t.Fatalf("timed out waiting for lookup %d to start", processed+batch)
			}
		}
		if processed+batch < numEvents {
			select {
			case <-osv.started:
				t.Fatal("more than maxConcurrency lookups started at once")
			case <-time.After(50 * time.Millisecond):
			}
		}
		for i := 0; i < batch; i++ {
			osv.release <- struct{}{}
		}
		processed += batch
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		osv.mu.Lock()
		calls, maxSeen := osv.numCalls, osv.maxSeen
		osv.mu.Unlock()
		if calls == numEvents {
			is.True(maxSeen <= maxConcurrency)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d QueryPurls calls, got %d", numEvents, calls)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
