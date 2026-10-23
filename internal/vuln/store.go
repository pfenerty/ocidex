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

// ListSBOMsToMatch returns up to limit SBOMs, ordered by ID after afterID, that
// have not been matched against the grype build built.
func (s *PGStore) ListSBOMsToMatch(ctx context.Context, built time.Time, afterID pgtype.UUID, limit int32) ([]SBOMDoc, error) {
	rows, err := s.q.ListSBOMsToMatch(ctx, repository.ListSBOMsToMatchParams{
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

// MatchedDBBuilt returns the grype build the last completed match pass was
// against (ok=false if none has completed).
func (s *PGStore) MatchedDBBuilt(ctx context.Context) (time.Time, bool, error) {
	ts, err := s.q.GetVulnMatchedDBBuilt(ctx)
	if err != nil {
		return time.Time{}, false, err
	}
	return ts.Time, ts.Valid, nil
}

// SetMatchedDBBuilt records a completed match pass against build built, and
// stamps the refresh time.
func (s *PGStore) SetMatchedDBBuilt(ctx context.Context, built time.Time) error {
	return s.q.SetVulnMatchedDBBuilt(ctx, timestamptz(built))
}

// UpsertVulnerability inserts or updates one vulnerability record.
func (s *PGStore) UpsertVulnerability(ctx context.Context, v Row) error {
	return s.q.UpsertVulnerability(ctx, vulnParams(v))
}

// MergeVulnerability writes one SBOM's view of a vulnerability and its
// references during a match pass against build built: replacing what another
// build wrote, merging with what this build already wrote (see the
// MergeVulnerability query).
func (s *PGStore) MergeVulnerability(ctx context.Context, v Row, built time.Time) error {
	p := vulnParams(v)
	b := timestamptz(built)
	if err := s.q.MergeVulnerability(ctx, repository.MergeVulnerabilityParams{
		ID:          p.ID,
		Aliases:     p.Aliases,
		CanonicalID: p.CanonicalID,
		Summary:     p.Summary,
		Details:     p.Details,
		Severity:    p.Severity,
		CvssScore:   p.CvssScore,
		PublishedAt: p.PublishedAt,
		ModifiedAt:  p.ModifiedAt,
		Raw:         p.Raw,
		CvssVector:  p.CvssVector,
		DbBuiltAt:   b,
	}); err != nil {
		return err
	}
	for _, ref := range v.References {
		if ref.URL == "" {
			continue
		}
		if err := s.q.MergeVulnerabilityRef(ctx, repository.MergeVulnerabilityRefParams{
			VulnerabilityID: v.ID,
			Type:            ref.Type,
			Url:             ref.URL,
			DbBuiltAt:       b,
		}); err != nil {
			return fmt.Errorf("merge ref: %w", err)
		}
	}
	return nil
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

// ReplacePackageVulns atomically replaces all mappings for a purl, across every
// Go symbol set (delete then insert in one transaction), so a reader never sees a
// purl with no vulns mid-refresh.
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

// MergePackageVulns writes mappings for a purl during a match pass against
// build built, without removing any: DeleteStaleMatches does that once the pass
// completes.
func (s *PGStore) MergePackageVulns(ctx context.Context, purl string, refs []PackageVulnRef, built time.Time) error {
	for _, ref := range refs {
		p := packageVulnParams(purl, ref)
		if err := s.q.MergePackageVuln(ctx, repository.MergePackageVulnParams{
			Purl:            p.Purl,
			GoSymbolSetID:   p.GoSymbolSetID,
			VulnerabilityID: p.VulnerabilityID,
			FixedVersion:    p.FixedVersion,
			FixState:        p.FixState,
			DbBuiltAt:       timestamptz(built),
		}); err != nil {
			return fmt.Errorf("merge mapping: %w", err)
		}
	}
	return nil
}

// DeleteStaleMatches deletes the mappings and references any build other than
// built wrote, in one transaction, returning how many mappings it removed. Call
// it only once every SBOM has been matched against built.
func (s *PGStore) DeleteStaleMatches(ctx context.Context, built time.Time) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	qtx := s.q.WithTx(tx)
	n, err := qtx.DeleteStalePackageVulns(ctx, timestamptz(built))
	if err != nil {
		return 0, fmt.Errorf("delete stale mappings: %w", err)
	}
	if _, err := qtx.DeleteStaleVulnerabilityRefs(ctx, timestamptz(built)); err != nil {
		return 0, fmt.Errorf("delete stale refs: %w", err)
	}
	return n, tx.Commit(ctx)
}

func packageVulnParams(purl string, ref PackageVulnRef) repository.UpsertPackageVulnParams {
	return repository.UpsertPackageVulnParams{
		Purl:            purl,
		GoSymbolSetID:   ref.GoSymbolSetID,
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

// SBOMGoSymbols returns, for every component of an SBOM that links a Go symbol
// set (ADR-050), its import path → normalized symbol names. An import path
// present with no symbols maps to an empty (non-nil) list. Sets shared by several
// components are loaded once.
func (s *PGStore) SBOMGoSymbols(ctx context.Context, sbomID pgtype.UUID) (map[GoSymbolKey]GoSymbolSet, error) {
	comps, err := s.q.ListSBOMGoSymbolSets(ctx, sbomID)
	if err != nil || len(comps) == 0 {
		return nil, err
	}
	setIDs := make([]int64, 0, len(comps))
	seen := map[int64]bool{}
	for _, c := range comps {
		if id := c.GoSymbolSetID.Int64; !seen[id] {
			seen[id] = true
			setIDs = append(setIDs, id)
		}
	}
	rows, err := s.q.ListGoSymbolSetSymbols(ctx, setIDs)
	if err != nil {
		return nil, err
	}
	sets := make(map[int64]map[string][]string, len(setIDs))
	for _, r := range rows {
		t := sets[r.SetID]
		if t == nil {
			t = map[string][]string{}
			sets[r.SetID] = t
		}
		if r.Name == "" {
			if t[r.ImportPath] == nil {
				t[r.ImportPath] = []string{}
			}
			continue
		}
		t[r.ImportPath] = append(t[r.ImportPath], r.Name)
	}
	out := make(map[GoSymbolKey]GoSymbolSet, len(comps))
	for _, c := range comps {
		id := c.GoSymbolSetID.Int64
		out[GoSymbolKey{Purl: c.Purl, FilePath: c.FilePath}] = GoSymbolSet{ID: id, Symbols: sets[id]}
	}
	return out, nil
}

// PruneOrphanGoSymbolSets deletes symbol sets no component links any more.
func (s *PGStore) PruneOrphanGoSymbolSets(ctx context.Context) (int64, error) {
	return s.q.PruneOrphanGoSymbolSets(ctx)
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
