package vuln

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/mod/semver"
)

// OSVQuerier is the OSV client surface the refresh needs. *Client satisfies it.
type OSVQuerier interface {
	QueryPurls(ctx context.Context, purls []string) (map[string][]string, error)
	GetVuln(ctx context.Context, id string) (*Record, error)
}

// Row is a vulnerability ready to persist (domain shape; the store adapter
// translates it to repository params).
type Row struct {
	ID          string
	Aliases     []string
	CanonicalID string
	Summary     string
	Details     string
	Severity    string
	CVSSScore   *float32
	Published   time.Time
	Modified    time.Time
	Raw         []byte
	References  []Reference
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
	// ListDistinctPurlTypes returns the distinct purl type tokens (e.g. "npm", "pypi").
	ListDistinctPurlTypes(ctx context.Context) ([]string, error)
	// ListDistinctComponentPurlsByTypes returns purls whose type matches any entry in types.
	ListDistinctComponentPurlsByTypes(ctx context.Context, types []string) ([]string, error)
	// ListUnknownPurlsForSBOM returns purls from the given SBOM not yet in package_vulnerability.
	ListUnknownPurlsForSBOM(ctx context.Context, sbomID pgtype.UUID) ([]string, error)
	// UpsertVulnerability inserts or updates one vulnerability record.
	UpsertVulnerability(ctx context.Context, v Row) error
	// DeleteVulnerabilityByID removes a withdrawn vulnerability and its cascade-linked rows.
	// No-op if the record does not exist.
	DeleteVulnerabilityByID(ctx context.Context, id string) error
	// ReplaceVulnerabilityRefs atomically replaces all references for a vulnerability.
	ReplaceVulnerabilityRefs(ctx context.Context, vulnID string, refs []Reference) error
	// ReplacePackageVulns atomically replaces all mappings for a purl.
	ReplacePackageVulns(ctx context.Context, purl string, refs []PackageVulnRef) error
	// LastRefreshedAt returns the last successful refresh time (ok=false if never).
	LastRefreshedAt(ctx context.Context) (t time.Time, ok bool, err error)
	// MarkRefreshed stamps the refresh as complete now.
	MarkRefreshed(ctx context.Context) error
	// GetEcosystemState returns the last CSV modified timestamp stored for an ecosystem.
	// ok=false means no state has been recorded yet (first run for that ecosystem).
	GetEcosystemState(ctx context.Context, ecosystem string) (t time.Time, ok bool, err error)
	// UpsertEcosystemState persists the latest CSV modified timestamp for an ecosystem.
	UpsertEcosystemState(ctx context.Context, ecosystem string, lastModifiedAt time.Time) error
}

// csvModifiedFetcher is the interface consumed by RefreshService for fetching
// per-ecosystem modified timestamps from the OSV bucket.
type csvModifiedFetcher interface {
	FetchMaxModifiedAt(ctx context.Context, ecosystem string) (time.Time, error)
}

// RefreshService rebuilds the package-keyed vulnerability store from OSV.
type RefreshService struct {
	store      Store
	osv        OSVQuerier
	logger     *slog.Logger
	csvFetcher csvModifiedFetcher // nil → full refresh (no incremental check)
}

// RefreshOption configures a RefreshService.
type RefreshOption func(*RefreshService)

// WithCSVFetcher enables incremental refresh: only ecosystems whose
// modified_id.csv has advanced since the last recorded state are re-queried.
func WithCSVFetcher(f csvModifiedFetcher) RefreshOption {
	return func(s *RefreshService) { s.csvFetcher = f }
}

// NewRefreshService constructs a RefreshService. Pass WithCSVFetcher to enable
// incremental refresh; without it every cycle re-queries all purls.
func NewRefreshService(store Store, osv OSVQuerier, logger *slog.Logger, opts ...RefreshOption) *RefreshService {
	if logger == nil {
		logger = slog.Default()
	}
	svc := &RefreshService{store: store, osv: osv, logger: logger}
	for _, o := range opts {
		o(svc)
	}
	return svc
}

// Refresh runs one refresh cycle. When a csvFetcher is configured it uses
// incremental mode: only purls from ecosystems whose modified_id.csv has
// advanced since the last recorded state are re-queried. Otherwise it
// re-queries every distinct purl. On success it stamps the refresh time.
func (s *RefreshService) Refresh(ctx context.Context) error {
	start := time.Now()

	var purls []string
	var ecosystemStates map[string]time.Time // populated only in incremental mode

	if s.csvFetcher != nil {
		var err error
		purls, ecosystemStates, err = s.selectChangedPurls(ctx)
		if err != nil {
			return err
		}
		if len(purls) == 0 {
			s.logger.Info("vuln refresh: all ecosystems up-to-date")
			return s.store.MarkRefreshed(ctx)
		}
	} else {
		var err error
		purls, err = s.store.ListDistinctComponentPurls(ctx)
		if err != nil {
			return fmt.Errorf("listing purls: %w", err)
		}
		if len(purls) == 0 {
			s.logger.Info("vuln refresh: no purls to scan")
			return s.store.MarkRefreshed(ctx)
		}
	}

	purlToIDs, err := s.osv.QueryPurls(ctx, purls)
	if err != nil {
		return fmt.Errorf("osv querybatch: %w", err)
	}

	// Hydrate each referenced vuln once (a popular CVE appears under many purls).
	records := s.hydrate(ctx, purlToIDs)

	affected, err := s.replaceMappings(ctx, purls, purlToIDs, records)
	if err != nil {
		return err
	}

	s.saveEcosystemStates(ctx, ecosystemStates)

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

// replaceMappings performs the delete-then-insert cycle for each purl and
// returns the number of purls that had at least one vulnerability mapping.
func (s *RefreshService) replaceMappings(ctx context.Context, purls []string, purlToIDs map[string][]string, records map[string]*Record) (int, error) {
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
				FixedVersion:    fixedVersionForPurl(rec, purl),
			})
		}
		if err := s.store.ReplacePackageVulns(ctx, purl, refs); err != nil {
			return 0, fmt.Errorf("replacing mappings for %s: %w", purl, err)
		}
		if len(refs) > 0 {
			affected++
		}
	}
	return affected, nil
}

// saveEcosystemStates persists per-ecosystem CSV modified timestamps so the
// next cycle can skip unchanged ecosystems. A zero time means the CSV fetch
// failed; that ecosystem is skipped so it retries on the next cycle.
func (s *RefreshService) saveEcosystemStates(ctx context.Context, ecosystemStates map[string]time.Time) {
	for eco, csvMax := range ecosystemStates {
		if csvMax.IsZero() {
			continue
		}
		if err := s.store.UpsertEcosystemState(ctx, eco, csvMax); err != nil {
			s.logger.Warn("vuln refresh: failed to save ecosystem state", "ecosystem", eco, "err", err)
		}
	}
}

// selectChangedPurls identifies which purls need refreshing based on
// per-ecosystem modified_id.csv timestamps. Returns the purls to refresh and a
// map of ecosystem → CSV max-modified-time for ecosystems that changed (used to
// update state after a successful cycle). A zero time in the map means the CSV
// fetch failed and state should not be updated.
func (s *RefreshService) selectChangedPurls(ctx context.Context) ([]string, map[string]time.Time, error) {
	purlTypes, err := s.store.ListDistinctPurlTypes(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("listing purl types: %w", err)
	}

	type purlEcosystems struct {
		purlType   string
		ecosystems []string
	}
	var known []purlEcosystems
	var unknownTypes []string
	for _, typ := range purlTypes {
		if ecos, ok := PurlTypeToOSVEcosystems(typ); ok {
			known = append(known, purlEcosystems{typ, ecos})
		} else {
			unknownTypes = append(unknownTypes, typ)
		}
	}

	ecosystemStates := make(map[string]time.Time)
	var changedTypes []string

	for _, te := range known {
		anyChanged := false
		for _, eco := range te.ecosystems {
			csvMax, err := s.csvFetcher.FetchMaxModifiedAt(ctx, eco)
			if err != nil {
				// On CSV fetch error include the ecosystem so we don't silently skip it.
				s.logger.Warn("vuln refresh: CSV fetch failed, including ecosystem", "ecosystem", eco, "err", err)
				anyChanged = true
				// Zero time → state not updated → retried next cycle.
				ecosystemStates[eco] = time.Time{}
				continue
			}

			stored, found, err := s.store.GetEcosystemState(ctx, eco)
			if err != nil {
				s.logger.Warn("vuln refresh: ecosystem state lookup failed, including", "ecosystem", eco, "err", err)
				anyChanged = true
				continue
			}

			if !found || csvMax.After(stored) {
				anyChanged = true
				ecosystemStates[eco] = csvMax
			}
		}
		if anyChanged {
			changedTypes = append(changedTypes, te.purlType)
		}
	}

	// Unknown purl types have no modified_id.csv; always include them.
	changedTypes = append(changedTypes, unknownTypes...)

	if len(changedTypes) == 0 {
		return nil, ecosystemStates, nil
	}

	purls, err := s.store.ListDistinctComponentPurlsByTypes(ctx, changedTypes)
	if err != nil {
		return nil, nil, fmt.Errorf("listing purls by changed types: %w", err)
	}
	return purls, ecosystemStates, nil
}

// LookupPurls runs the hydrate+replace cycle for a specific purl set without
// marking a global refresh. Used for ingest-time gap-filling.
func (s *RefreshService) LookupPurls(ctx context.Context, purls []string) error {
	if len(purls) == 0 {
		return nil
	}
	purlToIDs, err := s.osv.QueryPurls(ctx, purls)
	if err != nil {
		return fmt.Errorf("osv querybatch: %w", err)
	}
	records := s.hydrate(ctx, purlToIDs)
	for _, purl := range purls {
		ids := purlToIDs[purl]
		refs := make([]PackageVulnRef, 0, len(ids))
		for _, id := range ids {
			rec, ok := records[id]
			if !ok {
				continue
			}
			refs = append(refs, PackageVulnRef{
				VulnerabilityID: id,
				FixedVersion:    fixedVersionForPurl(rec, purl),
			})
		}
		if err := s.store.ReplacePackageVulns(ctx, purl, refs); err != nil {
			return fmt.Errorf("replacing mappings for %s: %w", purl, err)
		}
	}
	return nil
}

// hydrate fetches and upserts each unique vulnerability ID once. Records that
// fail to fetch or store are skipped (logged) rather than aborting the refresh,
// and are omitted from the returned map so callers never map to an unstored vuln.
//
// When a record yields UNKNOWN severity (e.g. Go security database advisories
// which carry no CVSS vectors), hydrate attempts to resolve severity from the
// record's GHSA or CVE aliases, which typically do carry CVSS data.
func (s *RefreshService) hydrate(ctx context.Context, purlToIDs map[string][]string) map[string]*Record {
	unique := make(map[string]struct{})
	for _, ids := range purlToIDs {
		for _, id := range ids {
			unique[id] = struct{}{}
		}
	}
	// aliasCache avoids re-fetching alias records when several primary records
	// share the same GHSA/CVE alias.
	aliasCache := make(map[string]*Record)
	records := make(map[string]*Record, len(unique))
	for id := range unique {
		rec, err := s.osv.GetVuln(ctx, id)
		if err != nil {
			// A single bad record shouldn't abort the whole cycle; skip it.
			s.logger.Warn("vuln refresh: hydrating record failed", "id", id, "err", err)
			continue
		}
		if rec.Withdrawn != "" {
			s.logger.Debug("vuln refresh: skipping withdrawn record", "id", id, "withdrawn", rec.Withdrawn)
			if err := s.store.DeleteVulnerabilityByID(ctx, id); err != nil {
				s.logger.Warn("vuln refresh: failed to delete withdrawn record", "id", id, "err", err)
			}
			continue
		}
		if toRow(rec).Severity == SeverityUnknown {
			rec = s.resolveAliasSeverity(ctx, rec, aliasCache)
		}
		row := toRow(rec)
		if err := s.store.UpsertVulnerability(ctx, row); err != nil {
			// Skip records we can't store rather than aborting the whole refresh.
			// Only stored vulns are recorded so phase 2 never emits a mapping that
			// would violate the package_vulnerability -> vulnerability foreign key.
			s.logger.Warn("vuln refresh: upserting record failed", "id", id, "err", err)
			continue
		}
		if err := s.store.ReplaceVulnerabilityRefs(ctx, id, row.References); err != nil {
			s.logger.Warn("vuln refresh: replacing refs failed", "id", id, "err", err)
		}
		records[id] = rec
	}
	return records
}

// resolveAliasSeverity attempts to find a CVSS vector by fetching GHSA then
// CVE aliases from OSV. When found it copies the alias's severity entries onto
// rec so that toRow derives the correct label. aliasCache prevents duplicate
// fetches when multiple primary records share an alias.
func (s *RefreshService) resolveAliasSeverity(ctx context.Context, rec *Record, aliasCache map[string]*Record) *Record {
	for _, prefix := range []string{"GHSA-", "CVE-"} {
		for _, alias := range rec.Aliases {
			if !strings.HasPrefix(alias, prefix) {
				continue
			}
			aliasRec, ok := aliasCache[alias]
			if !ok {
				var err error
				aliasRec, err = s.osv.GetVuln(ctx, alias)
				if err != nil || aliasRec == nil {
					if err != nil {
						s.logger.Debug("vuln refresh: alias fetch failed", "alias", alias, "err", err)
					}
					continue
				}
				aliasCache[alias] = aliasRec
			}
			if label, _ := DeriveSeverity(aliasRec.Severity); label != SeverityUnknown {
				rec.Severity = aliasRec.Severity
				return rec
			}
		}
	}
	return rec
}

func toRow(rec *Record) Row {
	label, score := DeriveSeverity(rec.Severity)
	if label == SeverityUnknown {
		// Fall back to plain-text severity present in database_specific blocks.
		// The Go security database uses this pattern instead of CVSS vectors.
		label = databaseSpecificSeverity(rec)
	}
	return Row{
		ID:          rec.ID,
		Aliases:     rec.Aliases,
		CanonicalID: canonicalID(rec.ID, rec.Aliases),
		Summary:     rec.Summary,
		Details:     rec.Details,
		Severity:    label,
		CVSSScore:   score,
		Published:   parseTime(rec.Published),
		Modified:    parseTime(rec.Modified),
		Raw:         rec.Raw,
		References:  rec.References,
	}
}

// canonicalID returns the best stable public identifier for a vulnerability:
// prefers CVE- alias, then GHSA-, then falls back to the native OSV ID.
func canonicalID(id string, aliases []string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "GHSA-") {
			return a
		}
	}
	return id
}

// databaseSpecificSeverity checks the record-level and then per-affected
// database_specific blocks for a plain-text severity label. Returns UNKNOWN
// when none is found.
func databaseSpecificSeverity(rec *Record) string {
	if s := normalizeSeverityLabel(rec.DatabaseSpecific.Severity); s != "" {
		return s
	}
	for _, aff := range rec.Affected {
		if s := normalizeSeverityLabel(aff.DatabaseSpecific.Severity); s != "" {
			return s
		}
	}
	return SeverityUnknown
}

// fixedVersionForPurl returns the fixed version from the SEMVER interval that
// contains the installed version encoded in purl. For advisories that patch
// multiple release branches in a single range (e.g. Go stdlib), this picks the
// correct branch's fix rather than the first one in document order. Falls back
// to firstFixedVersion when the version cannot be parsed or no SEMVER range
// contains it.
func fixedVersionForPurl(rec *Record, purl string) string {
	if rec == nil {
		return ""
	}
	installed := purlVersion(purl)
	if installed == "" {
		return firstFixedVersion(rec)
	}
	installedSV := normalizeSemver(installed)
	if !semver.IsValid(installedSV) {
		return firstFixedVersion(rec)
	}
	for _, aff := range rec.Affected {
		for _, rng := range aff.Ranges {
			if rng.Type != "SEMVER" {
				continue
			}
			if fixed := matchedFixed(rng.Events, installedSV); fixed != "" {
				return fixed
			}
		}
	}
	return firstFixedVersion(rec)
}

// matchedFixed walks the interleaved introduced/fixed event sequence for one
// SEMVER range and returns the original fixed version string from the interval
// that contains installedSV, or "" if installedSV is not in any interval.
func matchedFixed(events []Event, installedSV string) string {
	inRange := false
	for _, ev := range events {
		if ev.Introduced != "" {
			intro := normalizeSemver(ev.Introduced)
			inRange = semver.IsValid(intro) && semver.Compare(installedSV, intro) >= 0
		}
		if ev.Fixed != "" && inRange {
			fixedSV := normalizeSemver(ev.Fixed)
			if semver.IsValid(fixedSV) && semver.Compare(installedSV, fixedSV) < 0 {
				return ev.Fixed
			}
			inRange = false
		}
	}
	return ""
}

// purlVersion extracts the version component after "@" in a package URL.
func purlVersion(purl string) string {
	at := strings.LastIndex(purl, "@")
	if at < 0 {
		return ""
	}
	return purl[at+1:]
}

// normalizeSemver converts a bare version string to the "vX.Y.Z" form required
// by golang.org/x/mod/semver. Strips a leading "go" prefix and adds "v" if absent.
func normalizeSemver(v string) string {
	v = strings.TrimPrefix(v, "go")
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
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
