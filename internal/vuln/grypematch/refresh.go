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
	// API's ingest-time OSV lookup, so it bounds how long a new SBOM shows no
	// vulnerabilities.
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
	ListSBOMsToMatch(ctx context.Context, built time.Time, all bool, afterID pgtype.UUID, limit int32) ([]vuln.SBOMDoc, error)
	MarkSBOMMatched(ctx context.Context, sbomID pgtype.UUID, built time.Time) error
	MatchedDBBuilt(ctx context.Context) (time.Time, bool, error)
	SetMatchedDBBuilt(ctx context.Context, built time.Time) error
	ListDistinctComponentPurls(ctx context.Context) ([]string, error)
	UpsertVulnerability(ctx context.Context, v vuln.Row) error
	InsertVulnerabilityIfAbsent(ctx context.Context, v vuln.Row) (bool, error)
	ReplaceVulnerabilityRefs(ctx context.Context, vulnID string, refs []vuln.Reference) error
	ReplacePackageVulns(ctx context.Context, purl string, refs []vuln.PackageVulnRef) error
	AddPackageVulns(ctx context.Context, purl string, refs []vuln.PackageVulnRef) error
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
//   - when the open build differs from the one the store was last rebuilt from,
//     it re-matches every stored SBOM and rebuilds the store (a full re-match);
//   - otherwise each tick it matches only SBOMs ingested since (incremental).
//
// A newly disclosed CVE therefore reaches every stored SBOM on the next database
// build, without re-scanning any image.
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

// Step runs one iteration: a database check if due, then a full or incremental
// match. Exported for --once.
func (r *Refresher) Step(ctx context.Context) error {
	r.checkDB()
	m, built := r.db.Matcher()
	if m == nil {
		return errors.New("no grype database available yet")
	}
	stored, ok, err := r.store.MatchedDBBuilt(ctx)
	if err != nil {
		return fmt.Errorf("reading matched db build: %w", err)
	}
	if !ok || !stored.Equal(built) {
		return r.fullRematch(ctx, m, built)
	}
	return r.matchPending(ctx, m, built)
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

// fullRematch matches every stored SBOM against build and rebuilds the store
// from the result: every vulnerability row is rewritten with severity derived
// across all its matches, every purl's mappings are replaced (purls with no match
// any more are emptied), and orphaned vulnerabilities are pruned.
func (r *Refresher) fullRematch(ctx context.Context, m *Matcher, built time.Time) error {
	start := r.now()
	rows, maps := NewRowSet(), NewMappingSet()
	n, err := r.eachSBOM(ctx, m, built, true, func(f []Finding) error {
		rows.Add(f)
		maps.Add(f)
		return nil
	})
	if err != nil {
		return err
	}

	vulns := rows.Rows()
	for _, row := range vulns {
		if err := r.store.UpsertVulnerability(ctx, row); err != nil {
			return fmt.Errorf("upserting %s: %w", row.ID, err)
		}
		if err := r.store.ReplaceVulnerabilityRefs(ctx, row.ID, row.References); err != nil {
			return fmt.Errorf("replacing refs for %s: %w", row.ID, err)
		}
	}

	purls, err := r.store.ListDistinctComponentPurls(ctx)
	if err != nil {
		return fmt.Errorf("listing purls: %w", err)
	}
	mapping := maps.Mappings()
	for _, p := range union(purls, mapping) {
		if err := r.store.ReplacePackageVulns(ctx, p, mapping[p]); err != nil {
			return fmt.Errorf("replacing mappings for %s: %w", p, err)
		}
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
	r.logger.Info("vuln full re-match complete",
		"db_built", built, "sboms", n, "vulns", len(vulns), "affected_purls", len(mapping),
		"pruned", pruned, "pruned_symbol_sets", prunedSets, "duration_ms", r.now().Sub(start).Milliseconds())
	return nil
}

// matchPending matches SBOMs not yet matched against build (newly ingested) and
// adds their findings. It never removes or rewrites: one SBOM's view must not
// overwrite rows the last full re-match derived from every SBOM, so a new
// vulnerability row is inserted only when its ID is new.
func (r *Refresher) matchPending(ctx context.Context, m *Matcher, built time.Time) error {
	n, err := r.eachSBOM(ctx, m, built, false, func(f []Finding) error {
		for _, row := range Rows(f) {
			inserted, err := r.store.InsertVulnerabilityIfAbsent(ctx, row)
			if err != nil {
				return fmt.Errorf("inserting %s: %w", row.ID, err)
			}
			if inserted {
				if err := r.store.ReplaceVulnerabilityRefs(ctx, row.ID, row.References); err != nil {
					return fmt.Errorf("replacing refs for %s: %w", row.ID, err)
				}
			}
		}
		for purl, refs := range Mappings(f) {
			if err := r.store.AddPackageVulns(ctx, purl, refs); err != nil {
				return fmt.Errorf("adding mappings for %s: %w", purl, err)
			}
		}
		return nil
	})
	if n > 0 {
		r.logger.Info("vuln matched new sboms", "sboms", n, "db_built", built)
	}
	return err
}

// eachSBOM pages through the SBOMs to match (every SBOM when all is set), matches
// each, hands its findings to fn, and stamps it matched against build. An SBOM
// whose document grype cannot decode is logged and stamped anyway, so it is not
// retried every tick; it is retried on the next database build.
func (r *Refresher) eachSBOM(ctx context.Context, m *Matcher, built time.Time, all bool, fn func([]Finding) error) (int, error) {
	var after pgtype.UUID
	after.Valid = true // the zero UUID sorts first
	var n int
	for {
		docs, err := r.store.ListSBOMsToMatch(ctx, built, all, after, pageSize)
		if err != nil {
			return n, fmt.Errorf("listing sboms: %w", err)
		}
		for _, d := range docs {
			if err := ctx.Err(); err != nil {
				return n, err
			}
			syms, err := r.store.SBOMGoSymbols(ctx, d.ID)
			if err != nil {
				return n, fmt.Errorf("loading go symbols for %v: %w", d.ID, err)
			}
			findings, err := m.Match(ctx, prepare(d), syms)
			if err != nil {
				r.logger.Warn("vuln match: skipping sbom", "sbom_id", d.ID, "err", err)
			} else if err := fn(findings); err != nil {
				return n, err
			}
			if err := r.store.MarkSBOMMatched(ctx, d.ID, built); err != nil {
				return n, fmt.Errorf("marking %v matched: %w", d.ID, err)
			}
			n++
		}
		if len(docs) < pageSize {
			return n, nil
		}
		after = docs[len(docs)-1].ID
	}
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

// union returns purls plus any mapping key not among them. A mapping key outside
// the stored purls means grype reported a purl ocidex does not store verbatim;
// writing it is harmless (no component joins to it) and keeps the rebuild total.
func union(purls []string, mapping map[string][]vuln.PackageVulnRef) []string {
	seen := make(map[string]bool, len(purls))
	out := make([]string, 0, len(purls))
	for _, p := range purls {
		seen[p] = true
		out = append(out, p)
	}
	for p := range mapping {
		if !seen[p] {
			out = append(out, p)
		}
	}
	return out
}
