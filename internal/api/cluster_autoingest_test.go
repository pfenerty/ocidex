package api

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

// autoIngestClusters is a ClusterService whose cluster has auto-ingest on and
// whose IngestUnknown blocks until released, counting calls. Every other
// method is the nil embedded interface: auto-ingest must not reach them.
type autoIngestClusters struct {
	service.ClusterService
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	sawCtx  chan error
}

func (c *autoIngestClusters) Get(context.Context, string) (service.Cluster, error) {
	return service.Cluster{ID: "c1", Name: "prod", AutoIngest: true}, nil
}

func (c *autoIngestClusters) IngestUnknown(ctx context.Context, _ string, _ service.RunningImageSubmitter, _ service.IngestUnknownParams, _ service.VisibilityFilter) (service.IngestResult, error) {
	if c.calls.Add(1) == 1 {
		close(c.started)
	}
	select {
	case <-c.release:
	case <-ctx.Done():
		c.sawCtx <- ctx.Err()
	}
	return service.IngestResult{}, nil
}

type noopSubmitter struct{}

func (noopSubmitter) Submit(context.Context, scanner.ScanRequest) error { return nil }

func newAutoIngestHandler(t *testing.T) (*Handler, *autoIngestClusters, *scanner.AdhocWalks) {
	t.Helper()
	clusters := &autoIngestClusters{
		started: make(chan struct{}), release: make(chan struct{}), sawCtx: make(chan error, 1),
	}
	walks := scanner.NewAdhocWalks(4, time.Minute, slog.Default()).Named("cluster-ingests")
	if err := walks.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := &Handler{clusterService: clusters, scanSubmitter: noopSubmitter{}, clusterIngests: walks}
	return h, clusters, walks
}

// A snapshot that lands while the cluster's last auto-ingest is still running
// skips instead of stacking a second (ocidex-89c9.6).
func TestAutoIngestSkipsWhileRunning(t *testing.T) {
	is := is.New(t)
	h, clusters, walks := newAutoIngestHandler(t)

	// The request ctx ends as soon as the push returns, as a real one does.
	reqCtx, endRequest := context.WithCancel(context.Background())
	h.autoIngestAfterSnapshot(reqCtx, "c1")
	endRequest()
	<-clusters.started

	for range 5 {
		h.autoIngestAfterSnapshot(context.Background(), "c1")
	}
	close(clusters.release)
	is.NoErr(walks.Stop())
	is.Equal(clusters.calls.Load(), int32(1))
}

// Shutdown cancels a running auto-ingest and waits for it.
func TestAutoIngestCancelledOnShutdown(t *testing.T) {
	is := is.New(t)
	h, clusters, walks := newAutoIngestHandler(t)
	h.autoIngestAfterSnapshot(context.Background(), "c1")
	<-clusters.started

	is.NoErr(walks.Stop())
	select {
	case err := <-clusters.sawCtx:
		is.True(err != nil)
	default:
		t.Fatal("Stop returned before the ingest saw its context cancelled")
	}
}
