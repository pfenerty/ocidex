package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/mod/semver"
)

const semverRangeType = "SEMVER"

// OSVQuerier is the OSV client surface the refresh needs. *Client satisfies it.
type OSVQuerier interface {
	QueryPurls(ctx context.Context, purls []string) (map[string][]QueryRef, error)
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
	CVSSVector  string
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
	// ListUnknownComponentPurls returns all distinct component purls globally that
	// have no package_vulnerability entry (never successfully queried).
	ListUnknownComponentPurls(ctx context.Context) ([]string, error)
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
	// GetVulnerabilityModifiedAts bulk-fetches stored modified_at timestamps for
	// the given IDs. Returns only IDs that exist in the DB.
	GetVulnerabilityModifiedAts(ctx context.Context, ids []string) (map[string]time.Time, error)
	// GetVulnerabilitiesRaw bulk-fetches stored raw OSV JSON for the given IDs.
	// Returns only IDs that exist in the DB.
	GetVulnerabilitiesRaw(ctx context.Context, ids []string) (map[string]json.RawMessage, error)
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

	purlToRefs, err := s.osv.QueryPurls(ctx, purls)
	if err != nil {
		return fmt.Errorf("osv querybatch: %w", err)
	}
	purlToIDs := extractIDs(purlToRefs)

	// Hydrate each referenced vuln once (a popular CVE appears under many purls).
	records := s.hydrate(ctx, purlToRefs)

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

	// Always include purls with no vulnerability data (unknown state).
	unknownPurls, err := s.store.ListUnknownComponentPurls(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("listing unknown purls: %w", err)
	}

	if len(changedTypes) == 0 {
		if len(unknownPurls) == 0 {
			return nil, ecosystemStates, nil
		}
		return unknownPurls, ecosystemStates, nil
	}

	changedPurls, err := s.store.ListDistinctComponentPurlsByTypes(ctx, changedTypes)
	if err != nil {
		return nil, nil, fmt.Errorf("listing purls by changed types: %w", err)
	}
	return mergePurls(changedPurls, unknownPurls), ecosystemStates, nil
}

// mergePurls returns a deduplicated slice containing all entries from a followed by unique entries from b.
func mergePurls(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, p := range a {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	for _, p := range b {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// LookupPurls runs the hydrate+replace cycle for a specific purl set without
// marking a global refresh. Used for ingest-time gap-filling.
func (s *RefreshService) LookupPurls(ctx context.Context, purls []string) error {
	if len(purls) == 0 {
		return nil
	}
	purlToRefs, err := s.osv.QueryPurls(ctx, purls)
	if err != nil {
		return fmt.Errorf("osv querybatch: %w", err)
	}
	purlToIDs := extractIDs(purlToRefs)
	records := s.hydrate(ctx, purlToRefs)
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

// extractIDs strips the Modified field from querybatch results, producing the
// plain purl→IDs map used by replaceMappings.
func extractIDs(purlToRefs map[string][]QueryRef) map[string][]string {
	out := make(map[string][]string, len(purlToRefs))
	for purl, refs := range purlToRefs {
		ids := make([]string, len(refs))
		for i, r := range refs {
			ids[i] = r.ID
		}
		out[purl] = ids
	}
	return out
}

// hydrate fetches and upserts each unique vulnerability ID once. Records that
// fail to fetch or store are skipped (logged) rather than aborting the refresh,
// and are omitted from the returned map so callers never map to an unstored vuln.
//
// Records whose stored modified_at matches the querybatch-reported Modified
// timestamp are skipped for network fetches; their raw JSON is loaded from the
// DB instead, saving one GetVuln call per unchanged record per cycle.
//
// When a record yields UNKNOWN severity (e.g. Go security database advisories
// which carry no CVSS vectors), hydrate attempts to resolve severity from the
// record's GHSA or CVE aliases, which typically do carry CVSS data.
func (s *RefreshService) hydrate(ctx context.Context, purlToRefs map[string][]QueryRef) map[string]*Record {
	// Build unique ID set and record the querybatch-reported modified timestamp.
	modifiedByID := make(map[string]string)
	for _, refs := range purlToRefs {
		for _, r := range refs {
			modifiedByID[r.ID] = r.Modified
		}
	}

	toFetch, toLoad := s.partitionIDs(ctx, modifiedByID)

	aliasCache := make(map[string]*Record)
	records := make(map[string]*Record, len(modifiedByID))

	s.fetchVulns(ctx, toFetch, aliasCache, records)
	s.loadCachedVulns(ctx, toLoad, records)

	return records
}

// partitionIDs splits IDs into those that need a network fetch (new or changed)
// and those that can be reloaded from the DB (unchanged).
func (s *RefreshService) partitionIDs(ctx context.Context, modifiedByID map[string]string) (toFetch, toLoad []string) {
	ids := make([]string, 0, len(modifiedByID))
	for id := range modifiedByID {
		ids = append(ids, id)
	}
	storedAt, err := s.store.GetVulnerabilityModifiedAts(ctx, ids)
	if err != nil {
		s.logger.Warn("vuln refresh: modified_at bulk lookup failed, fetching all", "err", err)
		return ids, nil
	}
	for id, reported := range modifiedByID {
		stored, ok := storedAt[id]
		if ok && !stored.IsZero() && stored.UTC().Format(time.RFC3339) >= reported {
			toLoad = append(toLoad, id)
		} else {
			toFetch = append(toFetch, id)
		}
	}
	return toFetch, toLoad
}

// fetchVulns calls GetVuln for each ID, upserts, and populates records.
func (s *RefreshService) fetchVulns(ctx context.Context, ids []string, aliasCache map[string]*Record, records map[string]*Record) {
	for _, id := range ids {
		rec, err := s.osv.GetVuln(ctx, id)
		if err != nil {
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
			s.logger.Warn("vuln refresh: upserting record failed", "id", id, "err", err)
			continue
		}
		if err := s.store.ReplaceVulnerabilityRefs(ctx, id, row.References); err != nil {
			s.logger.Warn("vuln refresh: replacing refs failed", "id", id, "err", err)
		}
		records[id] = rec
	}
}

// loadCachedVulns reads raw OSV JSON from the DB for IDs whose stored
// modified_at matches the querybatch timestamp, avoiding a network call.
func (s *RefreshService) loadCachedVulns(ctx context.Context, ids []string, records map[string]*Record) {
	if len(ids) == 0 {
		return
	}
	raws, err := s.store.GetVulnerabilitiesRaw(ctx, ids)
	if err != nil {
		s.logger.Warn("vuln refresh: bulk raw load failed, skipping cached entries", "err", err)
		return
	}
	for id, raw := range raws {
		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			s.logger.Warn("vuln refresh: failed to unmarshal cached record", "id", id, "err", err)
			continue
		}
		records[id] = &rec
	}
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
			if label, _, _ := DeriveSeverity(aliasRec.Severity); label != SeverityUnknown {
				rec.Severity = aliasRec.Severity
				return rec
			}
		}
	}
	return rec
}

func toRow(rec *Record) Row {
	label, score, vector := DeriveSeverity(rec.Severity)
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
		CVSSVector:  vector,
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

// purlBase returns the purl with the version (and any qualifiers/subpath)
// stripped — everything before the last '@'.
func purlBase(purl string) string {
	at := strings.LastIndex(purl, "@")
	if at < 0 {
		return purl
	}
	return purl[:at]
}

// filteredAffected returns the subset of affected entries whose Package.Purl
// matches the base (version-stripped) of the queried purl. Returns nil when no
// entries carry a Package.Purl, meaning no confident package match is possible.
func filteredAffected(affected []Affected, purl string) []Affected {
	base := purlBase(purl)
	var matched []Affected
	for _, aff := range affected {
		if aff.Package.Purl != "" && strings.EqualFold(aff.Package.Purl, base) {
			matched = append(matched, aff)
		}
	}
	return matched
}

// fixedVersionForPurl returns the fixed version for the specific package
// identified by purl. It filters affected[] entries to those matching the
// queried package before searching ranges, so multi-package advisories (e.g.
// GHSA monorepos) cannot return another package's fixed version. Returns ""
// when no confident package match exists in the record.
func fixedVersionForPurl(rec *Record, purl string) string {
	if rec == nil {
		return ""
	}
	candidates := filteredAffected(rec.Affected, purl)
	if len(candidates) == 0 {
		return ""
	}
	installed := purlVersion(purl)
	if installed == "" {
		return firstFixedVersionFrom(candidates)
	}
	installedSV := normalizeSemver(installed)
	if !semver.IsValid(installedSV) {
		return firstFixedVersionFrom(candidates)
	}
	for _, aff := range candidates {
		for _, rng := range aff.Ranges {
			if rng.Type != semverRangeType {
				continue
			}
			if fixed, matched := matchedFixed(rng.Events, installedSV); matched {
				return fixed
			}
		}
	}
	return firstFixedVersionFrom(candidates)
}

// matchedFixed walks the introduced/fixed/last_affected boundaries for one
// SEMVER range and returns the original fixed version string from the interval
// that contains installedSV, and whether any interval contained it at all.
//
// OSV does not guarantee events[] arrives in sorted order in practice, so
// introduced and upper-bound (fixed/last_affected) events are each sorted by
// normalized version independently before being paired positionally into
// intervals. A last_affected upper bound is inclusive (unlike the exclusive
// fixed bound) and indicates the vulnerability is unresolved: matched is true
// but the returned fixed version is "".
func matchedFixed(events []Event, installedSV string) (fixed string, matched bool) {
	var introduced, upper []Event
	for _, ev := range events {
		switch {
		case ev.Introduced != "":
			introduced = append(introduced, ev)
		case ev.Fixed != "" || ev.LastAffected != "":
			upper = append(upper, ev)
		}
	}

	sortByVersionKey(introduced, func(ev Event) string { return ev.Introduced })
	sortByVersionKey(upper, func(ev Event) string {
		if ev.Fixed != "" {
			return ev.Fixed
		}
		return ev.LastAffected
	})

	for i, intro := range introduced {
		introSV := normalizeSemver(intro.Introduced)
		if !semver.IsValid(introSV) || semver.Compare(installedSV, introSV) < 0 {
			continue
		}

		if i >= len(upper) {
			return "", true // trailing introduced, no upper bound: still affected, open-ended
		}

		up := upper[i]
		upSV := normalizeSemver(upperVersion(up))
		if !semver.IsValid(upSV) {
			continue
		}

		switch {
		case up.Fixed != "" && semver.Compare(installedSV, upSV) < 0:
			return up.Fixed, true
		case up.LastAffected != "" && semver.Compare(installedSV, upSV) <= 0:
			return "", true
		}
	}
	return "", false
}

// upperVersion returns the version string carried by an upper-bound event
// (fixed or last_affected — exactly one is set per the OSV schema).
func upperVersion(ev Event) string {
	if ev.Fixed != "" {
		return ev.Fixed
	}
	return ev.LastAffected
}

// sortByVersionKey stable-sorts events ascending by the normalized semver
// extracted via key, leaving events with an unparseable version in place.
func sortByVersionKey(events []Event, key func(Event) string) {
	sort.SliceStable(events, func(i, j int) bool {
		a, b := normalizeSemver(key(events[i])), normalizeSemver(key(events[j]))
		if !semver.IsValid(a) || !semver.IsValid(b) {
			return false
		}
		return semver.Compare(a, b) < 0
	})
}

// purlVersion extracts the version component after "@" in a package URL,
// stripping any qualifiers ("?...") or subpath ("#...") suffix and
// percent-decoding the result per the purl spec.
func purlVersion(purl string) string {
	at := strings.LastIndex(purl, "@")
	if at < 0 {
		return ""
	}
	version := purl[at+1:]
	if end := strings.IndexAny(version, "?#"); end >= 0 {
		version = version[:end]
	}
	if decoded, err := url.PathUnescape(version); err == nil {
		version = decoded
	}
	return version
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

// firstFixedVersionFrom returns the first "fixed" event across a slice of
// affected entries. Callers are expected to pre-filter the slice to the
// relevant package before calling.
func firstFixedVersionFrom(affected []Affected) string {
	for _, aff := range affected {
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
