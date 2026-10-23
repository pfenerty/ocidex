package grypematch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/mainmodule"
	"github.com/pfenerty/ocidex/internal/vuln"
)

const (
	// tick is how often the worker looks for newly ingested SBOMs. It replaces the
	// API's ingest-time OSV lookup, so outside a pass against a new build it
	// bounds how long a new SBOM shows no vulnerabilities.
	tick = time.Minute
	// pageSize bounds how many raw SBOM documents are held at once.
	pageSize = 50
	// Backoff bounds after a failed database check, so an unreachable listing is
	// not hit on every tick.
	backoffFloor = 5 * time.Minute
	backoffCap   = 30 * time.Minute
)

// Store is the persistence the refresher needs; *vuln.PGStore satisfies it.
type Store interface {
	ListSBOMsToMatch(ctx context.Context, built time.Time, afterID pgtype.UUID, limit int32) ([]vuln.SBOMDoc, error)
	MarkSBOMMatched(ctx context.Context, sbomID pgtype.UUID, built time.Time) error
	MatchedDBBuilt(ctx context.Context) (time.Time, bool, error)
	SetMatchedDBBuilt(ctx context.Context, built time.Time) error
	MergeVulnerability(ctx context.Context, v vuln.Row, built time.Time) error
	MergePackageVulns(ctx context.Context, purl string, refs []vuln.PackageVulnRef, built time.Time) error
	DeleteStaleMatches(ctx context.Context, built time.Time) (int64, error)
	PruneOrphanVulnerabilities(ctx context.Context) (int64, error)
	SBOMGoSymbols(ctx context.Context, sbomID pgtype.UUID) (map[vuln.GoSymbolKey]vuln.GoSymbolSet, error)
	PruneOrphanGoSymbolSets(ctx context.Context) (int64, error)
}

// matcherSource yields the current matcher and its database build; *DB in
// production.
type matcherSource interface {
	Refresh() (bool, error)
	Matcher() (*Matcher, time.Time)
}

// Refresher keeps package_vulnerability in step with the grype database. It is
// meant to run as the leader-elected loop of the vuln-worker:
//
//   - every checkInterval it asks for a newer database build;
//   - each tick it matches every SBOM not yet matched against the open build —
//     all of them after a new build, only newly ingested ones otherwise — and
//     writes each SBOM's matches, stamped with the build, as it goes;
//   - when a pass against a new build completes, it deletes what other builds
//     wrote and prunes orphans.
//
// A pass is resumable: an SBOM is stamped matched once its matches are written,
// so a restart picks up where the last one stopped, and readers see the new
// build's matches as they land, beside the previous build's until the pass
// completes. A newly disclosed CVE therefore reaches every stored SBOM on the
// next database build, without re-scanning any image.
type Refresher struct {
	db            matcherSource
	store         Store
	checkInterval time.Duration
	logger        *slog.Logger

	nextCheck time.Time
	backoff   time.Duration
	now       func() time.Time
}

// NewRefresher returns a Refresher. checkInterval is how often to check for a
// newer database build.
func NewRefresher(db *DB, store Store, checkInterval time.Duration, logger *slog.Logger) *Refresher {
	return newRefresher(db, store, checkInterval, logger)
}

func newRefresher(db matcherSource, store Store, checkInterval time.Duration, logger *slog.Logger) *Refresher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Refresher{db: db, store: store, checkInterval: checkInterval, logger: logger, now: time.Now}
}

// Run steps on every tick until ctx is cancelled. Pass it to
// service.LeaderElect so exactly one replica writes.
func (r *Refresher) Run(ctx context.Context) {
	r.step(ctx)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.step(ctx)
		}
	}
}

func (r *Refresher) step(ctx context.Context) {
	if err := r.Step(ctx); err != nil && ctx.Err() == nil {
		r.logger.Error("vuln refresh failed", "err", err)
	}
}

// Step runs one iteration: a database check if due, then matching every SBOM
// not yet matched against the open build, then — if that completed a pass
// against a new build — the cleanup. Exported for --once.
func (r *Refresher) Step(ctx context.Context) error {
	r.checkDB()
	m, built := r.db.Matcher()
	if m == nil {
		return errors.New("no grype database available yet")
	}
	if err := r.matchPending(ctx, m, built); err != nil {
		return err
	}
	stored, ok, err := r.store.MatchedDBBuilt(ctx)
	if err != nil {
		return fmt.Errorf("reading matched db build: %w", err)
	}
	if ok && stored.Equal(built) {
		return nil
	}
	return r.completePass(ctx, built)
}

// checkDB asks for a newer build when one is due. A failure keeps whatever is
// open and backs off.
func (r *Refresher) checkDB() {
	now := r.now()
	if now.Before(r.nextCheck) {
		return
	}
	if _, err := r.db.Refresh(); err != nil {
		r.backoff = min(max(r.backoff*2, backoffFloor), backoffCap)
		r.nextCheck = now.Add(r.backoff)
		r.logger.Warn("grype db check failed; keeping the open database", "err", err, "retry_in", r.backoff)
		return
	}
	r.backoff = 0
	r.nextCheck = now.Add(r.checkInterval)
}

// matchPending matches every SBOM not yet matched against build and writes its
// matches, merged with what this build already wrote (see vuln.PGStore's
// MergeVulnerability), so the result does not depend on SBOM order.
func (r *Refresher) matchPending(ctx context.Context, m *Matcher, built time.Time) error {
	n, err := r.eachSBOM(ctx, m, built, func(f []Finding) error {
		for _, row := range Rows(f) {
			if err := r.store.MergeVulnerability(ctx, row, built); err != nil {
				return fmt.Errorf("merging %s: %w", row.ID, err)
			}
		}
		for purl, refs := range Mappings(f) {
			if err := r.store.MergePackageVulns(ctx, purl, refs, built); err != nil {
				return fmt.Errorf("merging mappings for %s: %w", purl, err)
			}
		}
		return nil
	})
	if n > 0 {
		r.logger.Info("vuln matched sboms", "sboms", n, "db_built", built)
	}
	return err
}

// completePass runs once every SBOM has been matched against build: what other
// builds wrote is no longer matched, so it goes, then orphans are pruned and the
// build is recorded as complete.
func (r *Refresher) completePass(ctx context.Context, built time.Time) error {
	stale, err := r.store.DeleteStaleMatches(ctx, built)
	if err != nil {
		return fmt.Errorf("deleting stale matches: %w", err)
	}
	pruned, err := r.store.PruneOrphanVulnerabilities(ctx)
	if err != nil {
		return fmt.Errorf("pruning: %w", err)
	}
	prunedSets, err := r.store.PruneOrphanGoSymbolSets(ctx)
	if err != nil {
		return fmt.Errorf("pruning go symbol sets: %w", err)
	}
	if err := r.store.SetMatchedDBBuilt(ctx, built); err != nil {
		return fmt.Errorf("recording matched build: %w", err)
	}
	r.logger.Info("vuln match pass complete",
		"db_built", built, "stale_mappings", stale, "pruned", pruned, "pruned_symbol_sets", prunedSets)
	return nil
}

// eachSBOM pages through the SBOMs not yet matched against build, matches each,
// hands its findings to fn, and stamps it matched. An SBOM
// whose document grype cannot decode is logged and stamped anyway, so it is not
// retried every tick; it is retried on the next database build.
func (r *Refresher) eachSBOM(ctx context.Context, m *Matcher, built time.Time, fn func([]Finding) error) (int, error) {
	var after pgtype.UUID
	after.Valid = true // the zero UUID sorts first
	var n int
	for {
		docs, err := r.store.ListSBOMsToMatch(ctx, built, after, pageSize)
		if err != nil {
			return n, fmt.Errorf("listing sboms: %w", err)
		}
		start := r.now()
		for _, d := range docs {
			if err := ctx.Err(); err != nil {
				return n, err
			}
			if err := r.matchOne(ctx, m, built, d, fn); err != nil {
				return n, err
			}
			n++
		}
		if len(docs) > 0 {
			r.logger.Info("vuln match page", "sboms", len(docs), "total", n, "db_built", built,
				"duration_ms", r.now().Sub(start).Milliseconds())
		}
		if len(docs) < pageSize {
			return n, nil
		}
		after = docs[len(docs)-1].ID
	}
}

// matchOne matches one SBOM, hands its findings to fn, and stamps it matched. A
// debug line breaks its time down, to tell matching from database writes.
func (r *Refresher) matchOne(ctx context.Context, m *Matcher, built time.Time, d vuln.SBOMDoc, fn func([]Finding) error) error {
	t0 := r.now()
	syms, err := r.store.SBOMGoSymbols(ctx, d.ID)
	if err != nil {
		return fmt.Errorf("loading go symbols for %v: %w", d.ID, err)
	}
	t1 := r.now()
	findings, err := m.Match(ctx, prepare(d), syms)
	t2 := r.now()
	if err != nil {
		r.logger.Warn("vuln match: skipping sbom", "sbom_id", d.ID, "err", err)
	} else if err := fn(findings); err != nil {
		return err
	}
	if err := r.store.MarkSBOMMatched(ctx, d.ID, built); err != nil {
		return fmt.Errorf("marking %v matched: %w", d.ID, err)
	}
	r.logger.Debug("vuln matched sbom", "sbom_id", d.ID, "bytes", len(d.Raw), "findings", len(findings),
		"symbols_ms", t1.Sub(t0).Milliseconds(), "match_ms", t2.Sub(t1).Milliseconds(),
		"write_ms", r.now().Sub(t2).Milliseconds())
	return nil
}

// prepare applies ingest's main-module version rule to the document grype
// matches, so a Go main module whose build info said "(devel)" is matched at the
// image's version — the version ocidex stored for it (internal/mainmodule).
// Anything that is not CycloneDX JSON, or needs no change, passes through as is.
func prepare(d vuln.SBOMDoc) []byte {
	if d.SubjectVersion == "" {
		return d.Raw
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(d.Raw), cdx.BOMFileFormatJSON).Decode(&bom); err != nil || bom.BOMFormat != cdx.BOMFormat {
		return d.Raw
	}
	if mainmodule.Apply(&bom, d.SubjectVersion) == 0 {
		return d.Raw
	}
	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).Encode(&bom); err != nil {
		return d.Raw
	}
	return buf.Bytes()
}
