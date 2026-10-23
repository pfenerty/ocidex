// Command loadgen generates a synthetic CycloneDX SBOM corpus for scale testing
// (ocidex-xxee.4): artifacts × versions × components, with shared base images,
// version-to-version churn, dependency edges, licenses, and real package names
// at vulnerable versions. The same -seed always produces the same corpus.
//
// It writes the SBOMs to a directory, or ingests them into a running instance
// through pkg/client. See docs/DEVELOPMENT.md "Synthetic corpus".
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pfenerty/ocidex/pkg/client"
)

type options struct {
	spec        Spec
	out         string
	url         string
	apiKey      string
	source      string
	concurrency int
}

func main() {
	opts := parseFlags(os.Args[1:])
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, opts)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) options {
	var o options
	fs := flag.NewFlagSet("loadgen", flag.ExitOnError)
	fs.Uint64Var(&o.spec.Seed, "seed", 1, "corpus seed; the same seed yields the same corpus")
	fs.IntVar(&o.spec.Artifacts, "artifacts", 50, "artifacts to generate")
	fs.IntVar(&o.spec.Versions, "versions", 100, "versions per artifact")
	fs.IntVar(&o.spec.Components, "components", 500, "components per SBOM")
	fs.IntVar(&o.spec.BaseImages, "base-images", 5, "shared base images the artifacts are spread over")
	fs.Float64Var(&o.spec.BaseShare, "base-share", 0.3, "fraction of each SBOM's components from its base image")
	fs.Float64Var(&o.spec.Churn, "churn", 0.05, "fraction of components that change version between consecutive versions")
	fs.StringVar(&o.out, "out", "", "write SBOMs under this directory instead of ingesting them")
	fs.StringVar(&o.url, "url", "http://localhost:8080", "API base URL to ingest into")
	fs.StringVar(&o.apiKey, "api-key", os.Getenv("OCIDEX_API_KEY"), "API key for ingest (default $OCIDEX_API_KEY)")
	fs.StringVar(&o.source, "source", "", "source id to ingest through")
	fs.IntVar(&o.concurrency, "concurrency", 4, "concurrent ingest requests")
	_ = fs.Parse(args)
	return o
}

func (o options) validate() error {
	s := o.spec
	switch {
	case s.Artifacts < 1, s.Versions < 1, s.Components < 1, s.BaseImages < 1:
		return errors.New("-artifacts, -versions, -components and -base-images must be at least 1")
	case s.BaseShare < 0 || s.BaseShare > 1, s.Churn < 0 || s.Churn > 1:
		return errors.New("-base-share and -churn must be between 0 and 1")
	case o.out == "" && (o.apiKey == "" || o.source == ""):
		return errors.New("ingesting needs -api-key and -source (or pass -out to write files)")
	case o.concurrency < 1:
		return errors.New("-concurrency must be at least 1")
	}
	return nil
}

func run(ctx context.Context, o options) error {
	if err := o.validate(); err != nil {
		return err
	}
	total := o.spec.Artifacts * o.spec.Versions
	slog.Info("generating corpus", "seed", o.spec.Seed, "sboms", total,
		"components_per_sbom", o.spec.Components, "artifacts", o.spec.Artifacts, "versions", o.spec.Versions)
	start := time.Now()
	sink := fileSink(o.out)
	if o.out == "" {
		sink = ingestSink(client.New(client.Config{BaseURL: strings.TrimSuffix(o.url, "/"), APIKey: o.apiKey}), o.source)
	}
	n, err := fanOut(ctx, o.spec, o.concurrency, sink, total)
	slog.Info("corpus done", "sboms", n, "duration", time.Since(start).Round(time.Second))
	return err
}

// fanOut feeds generated SBOMs to concurrency workers running sink, and returns
// how many succeeded. The first error stops the run.
func fanOut(ctx context.Context, spec Spec, concurrency int, sink func(context.Context, SBOM) error, total int) (int64, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	work := make(chan SBOM, concurrency)
	var done atomic.Int64
	var wg sync.WaitGroup
	for range concurrency {
		wg.Go(func() {
			for s := range work {
				if err := sink(ctx, s); err != nil {
					cancel(err)
					return
				}
				if n := done.Add(1); n%500 == 0 {
					slog.Info("progress", "sboms", n, "of", total)
				}
			}
		})
	}
	genErr := Generate(spec, func(s SBOM) error {
		select {
		case work <- s:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	})
	close(work)
	wg.Wait()
	if err := context.Cause(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return done.Load(), err
	}
	return done.Load(), genErr
}

func fileSink(dir string) func(context.Context, SBOM) error {
	return func(_ context.Context, s SBOM) error {
		path := filepath.Join(dir, strings.ReplaceAll(s.Artifact, "/", "_"), s.Version+".cdx.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		return os.WriteFile(path, s.Doc, 0o600)
	}
}

// rateLimitBackoff is the wait after the API's ingest rate limit
// (API_RATE_LIMIT_INGEST) answers 429, doubled on each repeat up to
// rateLimitMaxBackoff.
const (
	rateLimitBackoff    = 2 * time.Second
	rateLimitMaxBackoff = 30 * time.Second
)

func ingestSink(c client.Client, source string) func(context.Context, SBOM) error {
	return func(ctx context.Context, s SBOM) error {
		arch := "amd64"
		wait := rateLimitBackoff
		for {
			_, err := c.IngestSBOM(ctx, s.Doc, client.IngestSbomParams{
				Source: &source, Version: &s.Version, Architecture: &arch, Digest: &s.Digest,
			})
			var apiErr *client.APIError
			if !errors.As(err, &apiErr) || apiErr.Status != http.StatusTooManyRequests {
				if err != nil {
					return fmt.Errorf("ingesting %s %s: %w", s.Artifact, s.Version, err)
				}
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			wait = min(wait*2, rateLimitMaxBackoff)
		}
	}
}
