package vuln

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// PGStore is the Postgres-backed store the vuln-worker writes through.
type PGStore struct {
	pool *pgxpool.Pool
	q    *repository.Queries
}

// NewPGStore constructs a PGStore over the given pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool, q: repository.New(pool)}
}

// SBOMDoc is one stored SBOM document awaiting matching.
type SBOMDoc struct {
	ID             pgtype.UUID
	Raw            []byte
	SubjectVersion string
}

// ListDistinctComponentPurls returns every purl present in any SBOM, plus derived
// source purls.
func (s *PGStore) ListDistinctComponentPurls(ctx context.Context) ([]string, error) {
	return s.q.ListDistinctComponentPurls(ctx)
}

// ListSBOMsToMatch returns up to limit SBOMs, ordered by ID after afterID, that
// have not been matched against the grype build built — or every SBOM when all
// is set.
func (s *PGStore) ListSBOMsToMatch(ctx context.Context, built time.Time, all bool, afterID pgtype.UUID, limit int32) ([]SBOMDoc, error) {
	rows, err := s.q.ListSBOMsToMatch(ctx, repository.ListSBOMsToMatchParams{
		MatchAll:  all,
		DbBuiltAt: timestamptz(built),
		AfterID:   afterID,
		RowLimit:  limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]SBOMDoc, len(rows))
	for i, r := range rows {
		out[i] = SBOMDoc{ID: r.ID, Raw: r.RawBom, SubjectVersion: r.SubjectVersion.String}
	}
	return out, nil
}

// MarkSBOMMatched records that an SBOM has been matched against build built.
func (s *PGStore) MarkSBOMMatched(ctx context.Context, sbomID pgtype.UUID, built time.Time) error {
	return s.q.MarkSBOMVulnMatched(ctx, repository.MarkSBOMVulnMatchedParams{
		SbomID:    sbomID,
		DbBuiltAt: timestamptz(built),
	})
}

// MatchedDBBuilt returns the grype build package_vulnerability was last fully
// rebuilt from (ok=false if never).
func (s *PGStore) MatchedDBBuilt(ctx context.Context) (time.Time, bool, error) {
	ts, err := s.q.GetVulnMatchedDBBuilt(ctx)
	if err != nil {
		return time.Time{}, false, err
	}
	return ts.Time, ts.Valid, nil
}

// SetMatchedDBBuilt records a completed full re-match against build built, and
// stamps the refresh time.
func (s *PGStore) SetMatchedDBBuilt(ctx context.Context, built time.Time) error {
	return s.q.SetVulnMatchedDBBuilt(ctx, timestamptz(built))
}

// UpsertVulnerability inserts or updates one vulnerability record.
func (s *PGStore) UpsertVulnerability(ctx context.Context, v Row) error {
	return s.q.UpsertVulnerability(ctx, vulnParams(v))
}

// InsertVulnerabilityIfAbsent inserts a vulnerability record unless its ID
// already exists, reporting whether it inserted.
func (s *PGStore) InsertVulnerabilityIfAbsent(ctx context.Context, v Row) (bool, error) {
	n, err := s.q.InsertVulnerabilityIfAbsent(ctx, repository.InsertVulnerabilityIfAbsentParams(vulnParams(v)))
	return n > 0, err
}

func vulnParams(v Row) repository.UpsertVulnerabilityParams {
	// aliases is NOT NULL: a nil slice encodes as SQL NULL (the column DEFAULT
	// only applies when the column is omitted), so coalesce to an empty array.
	aliases := v.Aliases
	if aliases == nil {
		aliases = []string{}
	}
	return repository.UpsertVulnerabilityParams{
		ID:          v.ID,
		Aliases:     aliases,
		CanonicalID: v.CanonicalID,
		Summary:     text(v.Summary),
		Details:     text(v.Details),
		Severity:    text(v.Severity),
		CvssScore:   float4(v.CVSSScore),
		CvssVector:  text(v.CVSSVector),
		PublishedAt: timestamptz(v.Published),
		ModifiedAt:  timestamptz(v.Modified),
		Raw:         v.Raw,
	}
}

// ReplaceVulnerabilityRefs atomically replaces all references for a vulnerability
// (delete then insert in one transaction).
func (s *PGStore) ReplaceVulnerabilityRefs(ctx context.Context, vulnID string, refs []Reference) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	qtx := s.q.WithTx(tx)
	if err := qtx.DeleteVulnerabilityRefs(ctx, vulnID); err != nil {
		return fmt.Errorf("delete refs: %w", err)
	}
	for _, ref := range refs {
		if ref.URL == "" {
			continue
		}
		if err := qtx.InsertVulnerabilityRef(ctx, repository.InsertVulnerabilityRefParams{
			VulnerabilityID: vulnID,
			Type:            ref.Type,
			Url:             ref.URL,
		}); err != nil {
			return fmt.Errorf("insert ref: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// ReplacePackageVulns atomically replaces all mappings for a purl (delete then
// insert in one transaction) so a reader never sees a purl with no vulns
// mid-refresh.
func (s *PGStore) ReplacePackageVulns(ctx context.Context, purl string, refs []PackageVulnRef) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	qtx := s.q.WithTx(tx)
	if err := qtx.DeletePackageVulnsForPurl(ctx, purl); err != nil {
		return fmt.Errorf("delete mappings: %w", err)
	}
	for _, ref := range refs {
		if err := qtx.UpsertPackageVuln(ctx, packageVulnParams(purl, ref)); err != nil {
			return fmt.Errorf("insert mapping: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// AddPackageVulns upserts mappings for a purl without removing existing ones —
// the incremental path, where one new SBOM can only add to what the last full
// re-match established.
func (s *PGStore) AddPackageVulns(ctx context.Context, purl string, refs []PackageVulnRef) error {
	for _, ref := range refs {
		if err := s.q.UpsertPackageVuln(ctx, packageVulnParams(purl, ref)); err != nil {
			return fmt.Errorf("upsert mapping: %w", err)
		}
	}
	return nil
}

func packageVulnParams(purl string, ref PackageVulnRef) repository.UpsertPackageVulnParams {
	return repository.UpsertPackageVulnParams{
		Purl:            purl,
		VulnerabilityID: ref.VulnerabilityID,
		FixedVersion:    text(ref.FixedVersion),
		FixState:        text(ref.FixState),
	}
}

// PruneOrphanVulnerabilities deletes vulnerability rows no package maps to,
// returning how many it removed.
func (s *PGStore) PruneOrphanVulnerabilities(ctx context.Context) (int64, error) {
	return s.q.PruneOrphanVulnerabilities(ctx)
}

// LastRefreshedAt returns the last successful refresh time.
func (s *PGStore) LastRefreshedAt(ctx context.Context) (time.Time, bool, error) {
	ts, err := s.q.GetVulnRefreshState(ctx)
	if err != nil {
		return time.Time{}, false, err
	}
	if !ts.Valid {
		return time.Time{}, false, nil
	}
	return ts.Time, true, nil
}

func text(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func float4(f *float32) pgtype.Float4 {
	if f == nil {
		return pgtype.Float4{}
	}
	return pgtype.Float4{Float32: *f, Valid: true}
}

func timestamptz(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t, Valid: true}
}
