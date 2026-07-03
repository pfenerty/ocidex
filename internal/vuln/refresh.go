package vuln

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// OSVQuerier is the OSV client surface the refresh needs. *Client satisfies it.
type OSVQuerier interface {
	QueryPurls(ctx context.Context, purls []string) (map[string][]string, error)
	GetVuln(ctx context.Context, id string) (*Record, error)
}

// Row is a vulnerability ready to persist (domain shape; the store adapter
// translates it to repository params).
type Row struct {
	ID        string
	Aliases   []string
	Summary   string
	Details   string
	Severity  string
	CVSSScore *float32
	Published time.Time
	Modified  time.Time
	Raw       []byte
}

// PackageVulnRef is one (purl → vulnerability) mapping row.
type PackageVulnRef struct {
	VulnerabilityID string
	FixedVersion    string
}

// Store is the persistence surface the refresh loop needs.
type Store interface {
	// ListDistinctComponentPurls returns every purl present in any SBOM.
	ListDistinctComponentPurls(ctx context.Context) ([]string, error)
	// UpsertVulnerability inserts or updates one vulnerability record.
	UpsertVulnerability(ctx context.Context, v Row) error
	// ReplacePackageVulns atomically replaces all mappings for a purl.
	ReplacePackageVulns(ctx context.Context, purl string, refs []PackageVulnRef) error
	// LastRefreshedAt returns the last successful refresh time (ok=false if never).
	LastRefreshedAt(ctx context.Context) (t time.Time, ok bool, err error)
	// MarkRefreshed stamps the refresh as complete now.
	MarkRefreshed(ctx context.Context) error
}

// RefreshService rebuilds the package-keyed vulnerability store from OSV.
type RefreshService struct {
	store  Store
	osv    OSVQuerier
	logger *slog.Logger
}

// NewRefreshService constructs a RefreshService.
func NewRefreshService(store Store, osv OSVQuerier, logger *slog.Logger) *RefreshService {
	if logger == nil {
		logger = slog.Default()
	}
	return &RefreshService{store: store, osv: osv, logger: logger}
}

// Refresh runs one full refresh cycle: query every distinct purl against OSV,
// hydrate each referenced vulnerability once (deduped across purls), and
// replace the per-purl mappings. On success it stamps the refresh time.
func (s *RefreshService) Refresh(ctx context.Context) error {
	start := time.Now()
	purls, err := s.store.ListDistinctComponentPurls(ctx)
	if err != nil {
		return fmt.Errorf("listing purls: %w", err)
	}
	if len(purls) == 0 {
		s.logger.Info("vuln refresh: no purls to scan")
		return s.store.MarkRefreshed(ctx)
	}

	purlToIDs, err := s.osv.QueryPurls(ctx, purls)
	if err != nil {
		return fmt.Errorf("osv querybatch: %w", err)
	}

	// Hydrate each referenced vuln once (a popular CVE appears under many purls).
	records := s.hydrate(ctx, purlToIDs)

	// Replace per-purl mappings. Delete-then-insert prunes fixed/withdrawn vulns.
	var affected int
	for _, purl := range purls {
		ids := purlToIDs[purl]
		refs := make([]PackageVulnRef, 0, len(ids))
		for _, id := range ids {
			rec, ok := records[id]
			if !ok {
				// Vuln wasn't stored (hydration or upsert failed); skip its mapping
				// so the insert can't violate the foreign key.
				continue
			}
			refs = append(refs, PackageVulnRef{
				VulnerabilityID: id,
				FixedVersion:    firstFixedVersion(rec),
			})
		}
		if err := s.store.ReplacePackageVulns(ctx, purl, refs); err != nil {
			return fmt.Errorf("replacing mappings for %s: %w", purl, err)
		}
		if len(refs) > 0 {
			affected++
		}
	}

	if err := s.store.MarkRefreshed(ctx); err != nil {
		return fmt.Errorf("marking refreshed: %w", err)
	}
	s.logger.Info("vuln refresh complete",
		"purls", len(purls),
		"affected_purls", affected,
		"vulns", len(records),
		"duration_ms", time.Since(start).Milliseconds(),
	)
	return nil
}

// hydrate fetches and upserts each unique vulnerability ID once. Records that
// fail to fetch or store are skipped (logged) rather than aborting the refresh,
// and are omitted from the returned map so callers never map to an unstored vuln.
func (s *RefreshService) hydrate(ctx context.Context, purlToIDs map[string][]string) map[string]*Record {
	unique := make(map[string]struct{})
	for _, ids := range purlToIDs {
		for _, id := range ids {
			unique[id] = struct{}{}
		}
	}
	records := make(map[string]*Record, len(unique))
	for id := range unique {
		rec, err := s.osv.GetVuln(ctx, id)
		if err != nil {
			// A single bad record shouldn't abort the whole cycle; skip it.
			s.logger.Warn("vuln refresh: hydrating record failed", "id", id, "err", err)
			continue
		}
		if err := s.store.UpsertVulnerability(ctx, toRow(rec)); err != nil {
			// Skip records we can't store rather than aborting the whole refresh.
			// Only stored vulns are recorded so phase 2 never emits a mapping that
			// would violate the package_vulnerability -> vulnerability foreign key.
			s.logger.Warn("vuln refresh: upserting record failed", "id", id, "err", err)
			continue
		}
		records[id] = rec
	}
	return records
}

func toRow(rec *Record) Row {
	label, score := DeriveSeverity(rec.Severity)
	return Row{
		ID:        rec.ID,
		Aliases:   rec.Aliases,
		Summary:   rec.Summary,
		Details:   rec.Details,
		Severity:  label,
		CVSSScore: score,
		Published: parseTime(rec.Published),
		Modified:  parseTime(rec.Modified),
		Raw:       rec.Raw,
	}
}

// firstFixedVersion returns the first "fixed" event across a record's ranges.
// Best-effort: the fixed version is the same for a package regardless of which
// affected version pulled it in, so this is adequate for display.
func firstFixedVersion(rec *Record) string {
	if rec == nil {
		return ""
	}
	for _, aff := range rec.Affected {
		for _, rng := range aff.Ranges {
			for _, ev := range rng.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
