package tests

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
	natsc "github.com/testcontainers/testcontainers-go/modules/nats"

	"github.com/pfenerty/ocidex/internal/enrichment"
	gitenricher "github.com/pfenerty/ocidex/internal/enrichment/git"
	"github.com/pfenerty/ocidex/internal/enrichment/oci"
	"github.com/pfenerty/ocidex/internal/jobqueue"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/service"
	enrichmentworker "github.com/pfenerty/ocidex/internal/worker/enrichment"
)

const chainStreamName = "ocidex"

const chainTestCommitJSON = `{
	"sha": "cafef00d",
	"html_url": "https://github.com/owner/repo/commit/cafef00d",
	"commit": {
		"author": {"name": "Alice Author", "email": "alice@example.com", "date": "2026-01-01T00:00:00Z"},
		"committer": {"name": "Bob Committer", "email": "bob@example.com", "date": "2026-01-02T00:00:00Z"},
		"message": "Fix the thing"
	},
	"parents": []
}`

// chainTestSBOM is a minimal container-type CycloneDX SBOM with a digest —
// the only field the enrichment pipeline under test needs.
const chainTestSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"serialNumber": "urn:uuid:8a1d39e0-4711-4711-4711-471147114712",
	"metadata": {
		"component": {
			"type": "container",
			"name": "ghcr.io/example/chain@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			"version": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		}
	},
	"components": []
}`

// hostRewriteTransport redirects every request's scheme/host to target,
// keeping path and query. git.Enricher's base URL defaults to
// https://api.github.com and is only overridable from within package git
// (see git_test.go's `e.baseURL = srv.URL`); this test lives in package
// tests and can't reach that unexported field, so the redirect happens at
// the http.Client's Transport instead.
type hostRewriteTransport struct {
	target *url.URL
}

func (t *hostRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = t.target.Scheme
	req.URL.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

// ingestChainSBOM ingests chainTestSBOM via the real HTTP API and returns the
// new SBOM's ID.
func ingestChainSBOM(t *testing.T, pool *pgxpool.Pool) pgtype.UUID {
	t.Helper()
	is := is.New(t)

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	memberID := seedUser(t, pool, 9202, "chain-test-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "chain-test", "read-write")
	is.NoErr(err)

	resp, err := doWithAuth(t, http.MethodPost, srv.URL+"/api/v1/sboms", chainTestSBOM, memberKey)
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusCreated)
	var ingest map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&ingest))
	resp.Body.Close()

	var sbomID pgtype.UUID
	is.NoErr(sbomID.Scan(ingest["id"].(string)))
	return sbomID
}

// startGitWorker stands up a real git-scoped enrichment worker (catalog,
// dispatcher, "git"-partitioned EnrichJobService, jobqueue.Worker) mirroring
// cmd/git-worker/main.go's buildEnrichers and worker.go's wiring — including
// calling EnqueueDependents on completion, so the chain continues past git
// if git itself ever gains dependents. The only stub is the GitHub network
// leg (githubSrv). This is deliberately a separate catalog/dispatcher from
// any oci-metadata worker: a shared "all"-scoped catalog would let
// Dispatcher.ProcessOne run both enrichers off a single claim regardless of
// which enricher_name triggered it, defeating the point of this test.
func startGitWorker(t *testing.T, pool *pgxpool.Pool, natsClient *natspkg.Client, githubSrv *httptest.Server) service.EnrichJobService {
	t.Helper()

	store := repository.New(pool)
	ociReader := func(ctx context.Context, sbomID pgtype.UUID) (string, string, error) {
		e, err := store.GetEnrichment(ctx, repository.GetEnrichmentParams{
			SbomID:       sbomID,
			EnricherName: "oci-metadata",
		})
		if err != nil {
			return "", "", err
		}
		var meta oci.Metadata
		if err := json.Unmarshal(e.Data, &meta); err != nil {
			return "", "", err
		}
		return meta.SourceURL, meta.Revision, nil
	}

	targetURL, err := url.Parse(githubSrv.URL)
	if err != nil {
		t.Fatalf("parse github stub URL: %v", err)
	}

	gitReg := enrichment.NewCatalog()
	gitReg.Register(gitenricher.NewEnricher(
		gitenricher.WithOCIDataReader(ociReader),
		gitenricher.WithHTTPClient(&http.Client{Transport: &hostRewriteTransport{target: targetURL}}),
	))
	dispatcher := enrichment.NewDispatcher(store, gitReg)

	gitJobSvc := service.NewEnrichJobService(pool, "git")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	enrichProcessor := func(ctx context.Context, claim service.EnrichJobClaim) error {
		ref := enrichment.SubjectRef{
			SBOMId:         claim.SBOMId,
			ArtifactType:   claim.ArtifactType,
			ArtifactName:   claim.ArtifactName,
			Digest:         claim.Digest,
			IndexDigest:    claim.IndexDigest,
			SubjectVersion: claim.SubjectVersion,
			Architecture:   claim.Architecture,
			BuildDate:      claim.BuildDate,
		}
		if err := dispatcher.ProcessOne(ctx, ref); err != nil {
			return err
		}
		if err := gitJobSvc.FinishByID(ctx, claim.ID); err != nil {
			return err
		}
		enrichmentworker.EnqueueDependents(ctx, store, gitJobSvc, natsClient.JS, chainStreamName,
			claim.SBOMId, claim.Architecture, claim.BuildDate, "git", logger)
		return nil
	}

	worker := jobqueue.NewWorker(
		"enrich-hint-git-chain-test",
		natsClient, chainStreamName, gitJobSvc, enrichProcessor,
		jobqueue.Config{
			WorkerID:          "git-chain-test-worker",
			MaxConc:           1,
			PollInterval:      2 * time.Second,
			JobTimeout:        2 * time.Minute,
			MaxAttempts:       3,
			StuckThreshold:    5 * time.Minute,
			HintSubjectSuffix: ".enrich.hint",
			HintDurable:       "enrich-hint-git-chain-test",
		},
		logger,
	)
	if err := worker.Start(t.Context()); err != nil {
		t.Fatalf("start git worker: %v", err)
	}
	t.Cleanup(func() { _ = worker.Stop() })

	return gitJobSvc
}

// setupChainTest starts Postgres + NATS, ingests a container SBOM, and
// returns the pool, store, sbom ID, architecture/buildDate pair, NATS client,
// and logger shared by both subtests.
func setupChainTest(t *testing.T) (pool *pgxpool.Pool, store *repository.Queries, sbomID pgtype.UUID, architecture, buildDate string, natsClient *natspkg.Client, logger *slog.Logger) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireDocker(t)

	ctx := t.Context()
	pool, cleanDB := setupTestDB(t)
	t.Cleanup(cleanDB)

	natsContainer, err := natsc.Run(ctx, "docker.io/nats:latest")
	if err != nil {
		t.Fatalf("start nats container: %v", err)
	}
	t.Cleanup(func() { _ = natsContainer.Terminate(ctx) })

	natsURL, err := natsContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("nats connection string: %v", err)
	}
	natsClient, err = natspkg.Connect(natspkg.Config{
		URL:           natsURL,
		StreamName:    chainStreamName,
		EventTTLHours: 1,
	})
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	t.Cleanup(natsClient.Close)

	sbomID = ingestChainSBOM(t, pool)
	store = repository.New(pool)
	logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	architecture = "amd64"
	buildDate = "2026-01-01T00:00:00Z"
	return pool, store, sbomID, architecture, buildDate, natsClient, logger
}

// TestEnricherDependencyChain_GitEnqueuedAfterOCIMetadata proves the
// completion-driven dependency chain (ADR-0035) actually fires end-to-end:
// a successful oci-metadata enrichment causes EnqueueDependents to enqueue a
// git job, which a real git worker then picks up and successfully enriches
// using the oci-metadata row's sourceUrl/revision.
func TestEnricherDependencyChain_GitEnqueuedAfterOCIMetadata(t *testing.T) {
	pool, store, sbomID, architecture, buildDate, natsClient, logger := setupChainTest(t)
	is := is.New(t)
	ctx := t.Context()

	ociData, err := json.Marshal(oci.Metadata{
		SourceURL: "https://github.com/owner/repo",
		Revision:  "deadbeef",
	})
	is.NoErr(err)
	is.NoErr(store.UpsertEnrichment(ctx, repository.UpsertEnrichmentParams{
		SbomID:       sbomID,
		EnricherName: "oci-metadata",
		Status:       "success",
		Data:         ociData,
	}))

	gitJobSvc := service.NewEnrichJobService(pool, "git")
	enrichmentworker.EnqueueDependents(ctx, store, gitJobSvc, natsClient.JS, chainStreamName,
		sbomID, architecture, buildDate, "oci-metadata", logger)

	var jobCount int
	is.NoErr(pool.QueryRow(ctx,
		`SELECT count(*) FROM enrichment_jobs WHERE sbom_id = $1 AND enricher_name = 'git'`,
		sbomID,
	).Scan(&jobCount))
	is.Equal(jobCount, 1) // EnqueueDependents must enqueue exactly one git job

	githubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/commits/deadbeef" {
			t.Errorf("unexpected github request path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(chainTestCommitJSON))
	}))
	defer githubSrv.Close()

	startGitWorker(t, pool, natsClient, githubSrv)

	deadline := time.Now().Add(30 * time.Second)
	var gitRow repository.Enrichment
	for time.Now().Before(deadline) {
		gitRow, err = store.GetEnrichment(ctx, repository.GetEnrichmentParams{SbomID: sbomID, EnricherName: "git"})
		if err == nil && gitRow.Status == "success" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	is.NoErr(err)
	is.Equal(gitRow.Status, "success")

	var got struct {
		Resolved  bool   `json:"resolved"`
		Host      string `json:"host"`
		Owner     string `json:"owner"`
		Repo      string `json:"repo"`
		CommitSHA string `json:"commitSha"`
	}
	is.NoErr(json.Unmarshal(gitRow.Data, &got))
	is.True(got.Resolved)
	is.Equal(got.Host, "github.com")
	is.Equal(got.Owner, "owner")
	is.Equal(got.Repo, "repo")
	is.Equal(got.CommitSHA, "cafef00d")
}

// TestEnricherDependencyChain_NoGitJobOnOCIMetadataFailure proves the
// negative case: a failed oci-metadata enrichment must not cause the git
// dependent to be enqueued.
func TestEnricherDependencyChain_NoGitJobOnOCIMetadataFailure(t *testing.T) {
	pool, store, sbomID, architecture, buildDate, natsClient, logger := setupChainTest(t)
	is := is.New(t)
	ctx := t.Context()

	is.NoErr(store.UpsertEnrichment(ctx, repository.UpsertEnrichmentParams{
		SbomID:       sbomID,
		EnricherName: "oci-metadata",
		Status:       "error",
		ErrorMessage: pgtype.Text{String: "registry unreachable", Valid: true},
	}))

	gitJobSvc := service.NewEnrichJobService(pool, "git")
	enrichmentworker.EnqueueDependents(ctx, store, gitJobSvc, natsClient.JS, chainStreamName,
		sbomID, architecture, buildDate, "oci-metadata", logger)

	var jobCount int
	is.NoErr(pool.QueryRow(ctx,
		`SELECT count(*) FROM enrichment_jobs WHERE sbom_id = $1 AND enricher_name = 'git'`,
		sbomID,
	).Scan(&jobCount))
	is.Equal(jobCount, 0) // a failed prerequisite must not enqueue its dependent
}
