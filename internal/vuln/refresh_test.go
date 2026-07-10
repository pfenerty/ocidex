package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

var errFakeUpsert = errors.New("simulated upsert failure")

// fakeOSV is an in-memory OSVQuerier.
type fakeOSV struct {
	purlToRefs map[string][]QueryRef
	records    map[string]*Record
	getCalls   map[string]int

	err        error // when set, QueryPurls fails instead of returning results
	queryCalls int
}

func (f *fakeOSV) QueryPurls(_ context.Context, purls []string) (map[string][]QueryRef, error) {
	f.queryCalls++
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string][]QueryRef, len(purls))
	for _, p := range purls {
		out[p] = f.purlToRefs[p]
	}
	return out, nil
}

func (f *fakeOSV) GetVuln(_ context.Context, id string) (*Record, error) {
	if f.getCalls == nil {
		f.getCalls = map[string]int{}
	}
	f.getCalls[id]++
	return f.records[id], nil
}

// fakeStore records what the refresh persisted.
type fakeStore struct {
	purls             []string
	unknownPurls      []string // purls with no package_vulnerability rows
	vulns             map[string]Row
	mappings          map[string][]PackageVulnRef
	upsertErr         map[string]error // per-vuln-ID upsert failure to simulate bad records
	refreshed         bool
	last              time.Time
	lastOK            bool
	ecosystemState    map[string]time.Time       // ecosystem → stored last_modified_at
	upsertedEcos      map[string]time.Time       // ecosystem → value written by UpsertEcosystemState
	storedModifiedAts map[string]time.Time       // id → stored modified_at (for skip logic)
	storedRaw         map[string]json.RawMessage // id → stored raw JSON (for cache load)
	unknownForSBOM    []string                   // purls returned by ListUnknownPurlsForSBOM
	mu                sync.Mutex                 // guards mappings against concurrent ReplacePackageVulns calls
}

func newFakeStore(purls ...string) *fakeStore {
	return &fakeStore{
		purls:             purls,
		vulns:             map[string]Row{},
		mappings:          map[string][]PackageVulnRef{},
		ecosystemState:    map[string]time.Time{},
		upsertedEcos:      map[string]time.Time{},
		storedModifiedAts: map[string]time.Time{},
		storedRaw:         map[string]json.RawMessage{},
	}
}

func (s *fakeStore) ListDistinctComponentPurls(context.Context) ([]string, error) {
	return s.purls, nil
}

// ListDistinctPurlTypes extracts the type token from each stored purl.
func (s *fakeStore) ListDistinctPurlTypes(context.Context) ([]string, error) {
	seen := map[string]struct{}{}
	for _, p := range s.purls {
		// pkg:<type>/...
		after, ok := strings.CutPrefix(p, "pkg:")
		if !ok {
			continue
		}
		typ, _, _ := strings.Cut(after, "/")
		seen[typ] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	return out, nil
}

// ListDistinctComponentPurlsByTypes filters stored purls to those matching the types.
func (s *fakeStore) ListDistinctComponentPurlsByTypes(_ context.Context, types []string) ([]string, error) {
	want := map[string]struct{}{}
	for _, t := range types {
		want[t] = struct{}{}
	}
	var out []string
	for _, p := range s.purls {
		after, ok := strings.CutPrefix(p, "pkg:")
		if !ok {
			continue
		}
		typ, _, _ := strings.Cut(after, "/")
		if _, ok := want[typ]; ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *fakeStore) DeleteVulnerabilityByID(_ context.Context, id string) error {
	delete(s.vulns, id)
	return nil
}
func (s *fakeStore) UpsertVulnerability(_ context.Context, v Row) error {
	if err := s.upsertErr[v.ID]; err != nil {
		return err
	}
	s.vulns[v.ID] = v
	return nil
}
func (s *fakeStore) ReplaceVulnerabilityRefs(_ context.Context, _ string, _ []Reference) error {
	return nil
}
func (s *fakeStore) ReplacePackageVulns(_ context.Context, purl string, refs []PackageVulnRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mappings[purl] = refs
	return nil
}
func (s *fakeStore) ListUnknownComponentPurls(_ context.Context) ([]string, error) {
	return s.unknownPurls, nil
}

func (s *fakeStore) ListUnknownPurlsForSBOM(_ context.Context, _ pgtype.UUID) ([]string, error) {
	return s.unknownForSBOM, nil
}
func (s *fakeStore) LastRefreshedAt(context.Context) (time.Time, bool, error) {
	return s.last, s.lastOK, nil
}
func (s *fakeStore) MarkRefreshed(context.Context) error {
	s.refreshed = true
	return nil
}
func (s *fakeStore) GetEcosystemState(_ context.Context, ecosystem string) (time.Time, bool, error) {
	t, ok := s.ecosystemState[ecosystem]
	return t, ok, nil
}
func (s *fakeStore) UpsertEcosystemState(_ context.Context, ecosystem string, lastModifiedAt time.Time) error {
	s.upsertedEcos[ecosystem] = lastModifiedAt
	return nil
}
func (s *fakeStore) GetVulnerabilityModifiedAts(_ context.Context, ids []string) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(ids))
	for _, id := range ids {
		if t, ok := s.storedModifiedAts[id]; ok {
			out[id] = t
		}
	}
	return out, nil
}
func (s *fakeStore) GetVulnerabilitiesRaw(_ context.Context, ids []string) (map[string]json.RawMessage, error) {
	out := make(map[string]json.RawMessage, len(ids))
	for _, id := range ids {
		if raw, ok := s.storedRaw[id]; ok {
			out[id] = raw
		}
	}
	return out, nil
}

// fakeCSVFetcher is a configurable csvModifiedFetcher for tests.
type fakeCSVFetcher struct {
	times map[string]time.Time // ecosystem → CSV max modified time
	err   map[string]error
	calls []string // ecosystems fetched
}

func (f *fakeCSVFetcher) FetchMaxModifiedAt(_ context.Context, ecosystem string) (time.Time, error) {
	f.calls = append(f.calls, ecosystem)
	if err, ok := f.err[ecosystem]; ok {
		return time.Time{}, err
	}
	return f.times[ecosystem], nil
}

func TestRefreshMapsPurlsAndDedupesHydration(t *testing.T) {
	is := is.New(t)

	osv := &fakeOSV{
		purlToRefs: map[string][]QueryRef{
			"pkg:npm/a@1.0.0": {{ID: "CVE-1"}, {ID: "CVE-2"}},
			"pkg:npm/b@1.0.0": {{ID: "CVE-1"}}, // shares CVE-1 with a
			"pkg:npm/c@1.0.0": {},              // clean
		},
		records: map[string]*Record{
			"CVE-1": {
				ID:       "CVE-1",
				Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
				Affected: []Affected{{
					Package: AffectedPackage{Purl: "pkg:npm/a"},
					Ranges:  []Range{{Events: []Event{{Fixed: "1.0.1"}}}},
				}},
			},
			"CVE-2": {ID: "CVE-2"},
		},
	}
	store := newFakeStore("pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0")

	svc := NewRefreshService(store, osv, nil)
	is.NoErr(svc.Refresh(context.Background()))

	// CVE-1 hydrated exactly once despite appearing under two purls.
	is.Equal(osv.getCalls["CVE-1"], 1)
	// Both vulns persisted.
	is.Equal(len(store.vulns), 2)
	// Severity derived from the CVSS vector (9.8 -> CRITICAL).
	is.Equal(store.vulns["CVE-1"].Severity, "CRITICAL")
	// fixed_version propagated onto the mapping.
	is.Equal(store.mappings["pkg:npm/a@1.0.0"][0].FixedVersion, "1.0.1")
	// Clean purl got an empty mapping set (prunes any stale rows).
	is.Equal(len(store.mappings["pkg:npm/c@1.0.0"]), 0)
	is.True(store.refreshed)
}

func TestRefreshSkipsUnstorableVulnWithoutAborting(t *testing.T) {
	is := is.New(t)

	osv := &fakeOSV{
		purlToRefs: map[string][]QueryRef{
			"pkg:npm/a@1.0.0": {{ID: "CVE-GOOD"}, {ID: "RHSA-BAD"}}, // one good, one that fails to store
			"pkg:npm/b@1.0.0": {{ID: "CVE-GOOD"}},
		},
		records: map[string]*Record{
			"CVE-GOOD": {ID: "CVE-GOOD"},
			"RHSA-BAD": {ID: "RHSA-BAD"},
		},
	}
	store := newFakeStore("pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0")
	store.upsertErr = map[string]error{"RHSA-BAD": errFakeUpsert}

	svc := NewRefreshService(store, osv, nil)
	is.NoErr(svc.Refresh(context.Background())) // one bad record must not abort the run

	// Good vuln stored; bad one skipped.
	_, goodStored := store.vulns["CVE-GOOD"]
	is.True(goodStored)
	_, badStored := store.vulns["RHSA-BAD"]
	is.True(!badStored)

	// Mapping for the affected purl includes only the stored vuln (no dangling FK ref).
	refs := store.mappings["pkg:npm/a@1.0.0"]
	is.Equal(len(refs), 1)
	is.Equal(refs[0].VulnerabilityID, "CVE-GOOD")
	is.True(store.refreshed)
}

func TestRefreshNoPurlsStillMarks(t *testing.T) {
	is := is.New(t)
	store := newFakeStore()
	svc := NewRefreshService(store, &fakeOSV{purlToRefs: map[string][]QueryRef{}}, nil)
	is.NoErr(svc.Refresh(context.Background()))
	is.True(store.refreshed)
}

func TestSchedulerDue(t *testing.T) {
	is := is.New(t)
	store := newFakeStore()
	sch := NewScheduler(nil, store, time.Hour, nil)

	// Never refreshed -> due.
	store.lastOK = false
	due, err := sch.due(context.Background())
	is.NoErr(err)
	is.True(due)

	// Refreshed recently -> not due.
	store.lastOK = true
	store.last = time.Now().Add(-10 * time.Minute)
	due, err = sch.due(context.Background())
	is.NoErr(err)
	is.True(!due)

	// Refreshed long ago -> due.
	store.last = time.Now().Add(-2 * time.Hour)
	due, err = sch.due(context.Background())
	is.NoErr(err)
	is.True(due)
}

// Incremental refresh tests.

func TestIncrementalRefreshSkipsUnchangedEcosystem(t *testing.T) {
	is := is.New(t)

	csvTime := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	store := newFakeStore("pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0")
	// Stored state matches CSV time → no change.
	store.ecosystemState["npm"] = csvTime

	fetcher := &fakeCSVFetcher{times: map[string]time.Time{"npm": csvTime}}
	osv := &fakeOSV{purlToRefs: map[string][]QueryRef{}}

	svc := NewRefreshService(store, osv, nil, WithCSVFetcher(fetcher))
	is.NoErr(svc.Refresh(context.Background()))

	// No purls queried.
	is.Equal(len(store.mappings), 0)
	// Ecosystem state not updated (no change).
	is.Equal(len(store.upsertedEcos), 0)
	// Global refresh still marked.
	is.True(store.refreshed)
}

func TestIncrementalRefreshOnlyQueriesChangedEcosystem(t *testing.T) {
	is := is.New(t)

	oldTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newTime := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	// npm has changed, pypi has not.
	store := newFakeStore("pkg:npm/a@1.0.0", "pkg:pypi/requests@2.0.0")
	store.ecosystemState["npm"] = oldTime
	store.ecosystemState["PyPI"] = newTime // PyPI is current

	fetcher := &fakeCSVFetcher{times: map[string]time.Time{
		"npm":  newTime, // advanced → changed
		"PyPI": newTime, // same → no change
	}}
	osv := &fakeOSV{
		purlToRefs: map[string][]QueryRef{
			"pkg:npm/a@1.0.0": {{ID: "CVE-1"}},
		},
		records: map[string]*Record{"CVE-1": {ID: "CVE-1"}},
	}

	svc := NewRefreshService(store, osv, nil, WithCSVFetcher(fetcher))
	is.NoErr(svc.Refresh(context.Background()))

	// npm purl was refreshed.
	is.True(len(store.mappings["pkg:npm/a@1.0.0"]) > 0)
	// pypi purl was NOT touched.
	_, pypiMapped := store.mappings["pkg:pypi/requests@2.0.0"]
	is.True(!pypiMapped)

	// npm ecosystem state updated; PyPI not (unchanged).
	is.Equal(store.upsertedEcos["npm"], newTime)
	_, pypiUpdated := store.upsertedEcos["PyPI"]
	is.True(!pypiUpdated)
	is.True(store.refreshed)
}

func TestIncrementalRefreshFirstRunIncludesAllEcosystems(t *testing.T) {
	is := is.New(t)

	csvTime := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	// No stored state → first run → all ecosystems treated as changed.
	store := newFakeStore("pkg:npm/a@1.0.0")

	fetcher := &fakeCSVFetcher{times: map[string]time.Time{"npm": csvTime}}
	osv := &fakeOSV{
		purlToRefs: map[string][]QueryRef{"pkg:npm/a@1.0.0": {{ID: "CVE-1"}}},
		records:    map[string]*Record{"CVE-1": {ID: "CVE-1"}},
	}

	svc := NewRefreshService(store, osv, nil, WithCSVFetcher(fetcher))
	is.NoErr(svc.Refresh(context.Background()))

	is.True(len(store.mappings["pkg:npm/a@1.0.0"]) > 0)
	is.Equal(store.upsertedEcos["npm"], csvTime)
	is.True(store.refreshed)
}

func TestIncrementalRefreshUnknownPurlTypeAlwaysIncluded(t *testing.T) {
	is := is.New(t)

	// "oci" is not a known purl type in our ecosystem map.
	store := newFakeStore("pkg:oci/myimage@sha256:abc")

	// fetcher will not be called for "oci" (unknown type has no CSV URL).
	fetcher := &fakeCSVFetcher{times: map[string]time.Time{}}
	osv := &fakeOSV{
		purlToRefs: map[string][]QueryRef{"pkg:oci/myimage@sha256:abc": {}},
	}

	svc := NewRefreshService(store, osv, nil, WithCSVFetcher(fetcher))
	is.NoErr(svc.Refresh(context.Background()))

	// Unknown type was included → mappings replaced.
	_, touched := store.mappings["pkg:oci/myimage@sha256:abc"]
	is.True(touched)
	// No CSV was fetched for "oci".
	is.Equal(len(fetcher.calls), 0)
	is.True(store.refreshed)
}

func TestSelectChangedPurls_IncludesUnknownPurls(t *testing.T) {
	is := is.New(t)

	store := newFakeStore("pkg:npm/new@1.0.0")
	store.unknownPurls = []string{"pkg:npm/new@1.0.0"}
	// npm CSV unchanged: same timestamp stored and returned by fake fetcher.
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	store.ecosystemState = map[string]time.Time{"npm": now}
	fetcher := &fakeCSVFetcher{times: map[string]time.Time{"npm": now}}

	svc := NewRefreshService(store, &fakeOSV{purlToRefs: map[string][]QueryRef{}}, nil, WithCSVFetcher(fetcher))

	purls, _, err := svc.selectChangedPurls(context.Background())
	is.NoErr(err)
	is.Equal(len(purls), 1)
	is.Equal(purls[0], "pkg:npm/new@1.0.0")
}

// TestResolveAliasSeverity verifies that records without CVSS data (e.g. Go
// security database advisories) resolve severity from GHSA or CVE aliases.
func TestResolveAliasSeverity(t *testing.T) {
	is := is.New(t)

	ghsaRec := &Record{
		ID:       "GHSA-xx11-yy22-zz33",
		Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
	}
	cveRec := &Record{
		ID:       "CVE-2024-9999",
		Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"}},
	}
	osv := &fakeOSV{
		records: map[string]*Record{
			"GHSA-xx11-yy22-zz33": ghsaRec,
			"CVE-2024-9999":       cveRec,
		},
	}
	svc := NewRefreshService(newFakeStore(), osv, nil)
	aliasCache := map[string]*Record{}

	// GO- record with no CVSS, GHSA alias available → should borrow GHSA severity.
	goRec := &Record{
		ID:      "GO-2024-1234",
		Aliases: []string{"GHSA-xx11-yy22-zz33", "CVE-2024-9999"},
	}
	resolved := svc.resolveAliasSeverity(context.Background(), goRec, aliasCache)
	label, _, vector := DeriveSeverity(resolved.Severity)
	is.Equal(label, "HIGH") // CVSS 7.5 → HIGH
	is.Equal(vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")

	// GHSA alias should be cached; no second fetch.
	is.Equal(osv.getCalls["GHSA-xx11-yy22-zz33"], 1)
	is.Equal(osv.getCalls["CVE-2024-9999"], 0) // GHSA resolved first; CVE not fetched

	// Second call reuses alias cache for the same GHSA.
	goRec2 := &Record{
		ID:      "GO-2024-5678",
		Aliases: []string{"GHSA-xx11-yy22-zz33"},
	}
	svc.resolveAliasSeverity(context.Background(), goRec2, aliasCache)
	is.Equal(osv.getCalls["GHSA-xx11-yy22-zz33"], 1) // still 1 — cache hit

	// Record with no useful aliases stays UNKNOWN.
	noAliasRec := &Record{ID: "GO-2024-0000", Aliases: []string{"GHSA-missing"}}
	resolved2 := svc.resolveAliasSeverity(context.Background(), noAliasRec, map[string]*Record{})
	label2, _, _ := DeriveSeverity(resolved2.Severity)
	is.Equal(label2, SeverityUnknown)
}

// TestRefreshAliasSeverityIntegration verifies that a full refresh cycle resolves
// severity from aliases when the primary record lacks CVSS.
func TestRefreshAliasSeverityIntegration(t *testing.T) {
	is := is.New(t)

	osv := &fakeOSV{
		purlToRefs: map[string][]QueryRef{
			"pkg:golang/stdlib@1.21.0": {{ID: "GO-2024-0001"}},
		},
		records: map[string]*Record{
			"GO-2024-0001": {
				ID:      "GO-2024-0001",
				Aliases: []string{"GHSA-aa11-bb22-cc33", "CVE-2024-1111"},
			},
			"GHSA-aa11-bb22-cc33": {
				ID:       "GHSA-aa11-bb22-cc33",
				Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			},
		},
	}
	store := newFakeStore("pkg:golang/stdlib@1.21.0")

	svc := NewRefreshService(store, osv, nil)
	is.NoErr(svc.Refresh(context.Background()))

	// Primary record stored with severity resolved from GHSA alias.
	row, ok := store.vulns["GO-2024-0001"]
	is.True(ok)
	is.Equal(row.Severity, SeverityCritical) // CVSS 9.8 → CRITICAL
	// Vector persisted from the GHSA alias, not re-derived from the primary
	// record's raw JSON (which has no CVSS block of its own).
	is.Equal(row.CVSSVector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

	// CVE alias was never fetched (GHSA resolved first).
	is.Equal(osv.getCalls["CVE-2024-1111"], 0)
}

// TestToRowDatabaseSpecificSeverityFallback verifies that records without a
// CVSS vector (e.g. Go security database advisories) pick up severity from
// database_specific.severity instead of falling through to UNKNOWN.
func TestToRowDatabaseSpecificSeverityFallback(t *testing.T) {
	is := is.New(t)

	// Record-level database_specific (some ecosystems use this).
	recLevel := &Record{
		ID:               "GO-2024-0001",
		DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
	}
	row := toRow(recLevel)
	is.Equal(row.Severity, SeverityHigh)

	// Per-affected database_specific — used by the Go security database.
	affLevel := &Record{
		ID: "GO-2024-0002",
		Affected: []Affected{
			{DatabaseSpecific: DatabaseSpecific{Severity: "medium"}},
		},
	}
	row = toRow(affLevel)
	is.Equal(row.Severity, SeverityMedium)

	// Record-level wins over affected-level when both are present.
	both := &Record{
		ID:               "GO-2024-0003",
		DatabaseSpecific: DatabaseSpecific{Severity: "CRITICAL"},
		Affected: []Affected{
			{DatabaseSpecific: DatabaseSpecific{Severity: "LOW"}},
		},
	}
	row = toRow(both)
	is.Equal(row.Severity, SeverityCritical)

	// CVSS vector still wins when present; database_specific not consulted.
	withCVSS := &Record{
		ID:               "CVE-2024-9999",
		Severity:         []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		DatabaseSpecific: DatabaseSpecific{Severity: "LOW"},
	}
	row = toRow(withCVSS)
	is.Equal(row.Severity, SeverityCritical) // CVSS 9.8 → CRITICAL, not LOW
	is.Equal(row.CVSSVector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

	// Truly unknown (no CVSS, no database_specific) still returns UNKNOWN.
	unknown := &Record{ID: "GO-2024-0004"}
	row = toRow(unknown)
	is.Equal(row.Severity, SeverityUnknown)
	is.Equal(row.CVSSVector, "")
}

func TestMatchedFixed(t *testing.T) {
	is := is.New(t)

	// Multi-interval events: [0, 1.24.13), [1.25.0-0, 1.25.7), [1.26.0-rc.1, 1.26.0-rc.3)
	sortedEvents := []Event{
		{Introduced: "0"},
		{Fixed: "1.24.13"},
		{Introduced: "1.25.0-0"},
		{Fixed: "1.25.7"},
		{Introduced: "1.26.0-rc.1"},
		{Fixed: "1.26.0-rc.3"},
	}

	// Same intervals, shuffled: OSV does not guarantee event order.
	unsortedEvents := []Event{
		{Fixed: "1.26.0-rc.3"},
		{Introduced: "0"},
		{Fixed: "1.25.7"},
		{Introduced: "1.26.0-rc.1"},
		{Introduced: "1.25.0-0"},
		{Fixed: "1.24.13"},
	}

	lastAffectedEvents := []Event{
		{Introduced: "1.0.0"},
		{LastAffected: "1.5.0"},
	}

	// Mixed record: one last_affected interval with no fix, and a separate
	// interval in the same events slice with a real fixed version. Precedence
	// must be decided per matched interval, not by falling through to any
	// fixed version found elsewhere in the slice.
	mixedEvents := []Event{
		{Introduced: "1.0.0"},
		{LastAffected: "1.5.0"},
		{Introduced: "2.0.0"},
		{Fixed: "2.3.0"},
	}

	tests := []struct {
		name        string
		events      []Event
		installedSV string
		wantFixed   string
		wantMatched bool
	}{
		{"sorted mid interval", sortedEvents, "v1.25.4", "1.25.7", true},
		{"sorted first interval", sortedEvents, "v1.14.8", "1.24.13", true},
		{"sorted prerelease interval", sortedEvents, "v1.26.0-rc.2", "1.26.0-rc.3", true},
		{"sorted at fix boundary not in range", sortedEvents, "v1.25.7", "", false},
		{"sorted past all intervals", sortedEvents, "v2.0.0", "", false},

		{"unsorted mid interval", unsortedEvents, "v1.25.4", "1.25.7", true},
		{"unsorted first interval", unsortedEvents, "v1.14.8", "1.24.13", true},
		{"unsorted prerelease interval", unsortedEvents, "v1.26.0-rc.2", "1.26.0-rc.3", true},
		{"unsorted at fix boundary not in range", unsortedEvents, "v1.25.7", "", false},
		{"unsorted past all intervals", unsortedEvents, "v2.0.0", "", false},

		{"last_affected inclusive upper bound in range", lastAffectedEvents, "v1.5.0", "", true},
		{"last_affected mid range", lastAffectedEvents, "v1.2.0", "", true},
		{"last_affected below introduced not matched", lastAffectedEvents, "v0.9.0", "", false},
		{"last_affected past last_affected not matched", lastAffectedEvents, "v1.6.0", "", false},

		{"mixed: version in last_affected interval returns no fix, not the other interval's fix", mixedEvents, "v1.2.0", "", true},
		{"mixed: version in fixed interval returns its fix", mixedEvents, "v2.1.0", "2.3.0", true},
		{"mixed: version between intervals not matched", mixedEvents, "v1.8.0", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFixed, gotMatched := matchedFixed(tt.events, tt.installedSV)
			is.Equal(gotFixed, tt.wantFixed)
			is.Equal(gotMatched, tt.wantMatched)
		})
	}
}

func TestFixedVersionForPurl(t *testing.T) {
	is := is.New(t)

	rec := &Record{
		ID: "GO-2026-4337",
		Affected: []Affected{
			{
				Package: AffectedPackage{Purl: "pkg:golang/stdlib"},
				Ranges: []Range{
					{
						Type: semverRangeType,
						Events: []Event{
							{Introduced: "0"},
							{Fixed: "1.24.13"},
							{Introduced: "1.25.0-0"},
							{Fixed: "1.25.7"},
						},
					},
				},
			},
		},
	}

	// 1.25.x purl gets the 1.25.x fix
	is.Equal(fixedVersionForPurl(rec, "pkg:golang/stdlib@1.25.4"), "1.25.7")

	// Qualifiers after the version must not break SEMVER matching
	is.Equal(fixedVersionForPurl(rec, "pkg:golang/stdlib@1.25.4?os=linux"), "1.25.7")

	// Old purl gets the 1.24.x fix
	is.Equal(fixedVersionForPurl(rec, "pkg:golang/stdlib@1.14.8"), "1.24.13")

	// "go" prefix in purl version (some purls carry it)
	is.Equal(fixedVersionForPurl(rec, "pkg:golang/stdlib@go1.25.4"), "1.25.7")

	// Purl with no @ → purlBase == "pkg:golang/stdlib", matched; no version → firstFixedVersionFrom
	is.Equal(fixedVersionForPurl(rec, "pkg:golang/stdlib"), "1.24.13")

	// Purl with non-semver version → no SEMVER match → firstFixedVersionFrom
	is.Equal(fixedVersionForPurl(rec, "pkg:golang/stdlib@abc123commit"), "1.24.13")

	// nil record
	is.Equal(fixedVersionForPurl(nil, "pkg:golang/stdlib@1.25.4"), "")

	// Non-SEMVER range → no SEMVER interval found, falls back to firstFixedVersionFrom.
	gitRec := &Record{
		ID: "GO-2026-9999",
		Affected: []Affected{
			{
				Package: AffectedPackage{Purl: "pkg:golang/stdlib"},
				Ranges: []Range{
					{
						Type: "GIT",
						Events: []Event{
							{Introduced: "abc"},
							{Fixed: "def"},
						},
					},
				},
			},
		},
	}
	is.Equal(fixedVersionForPurl(gitRec, "pkg:golang/stdlib@1.25.4"), "def")
}

func TestFixedVersionForPurlLastAffectedNoFix(t *testing.T) {
	is := is.New(t)

	rec := &Record{
		ID: "GHSA-last-affected",
		Affected: []Affected{
			{
				Package: AffectedPackage{Purl: "pkg:npm/pkg-c"},
				Ranges: []Range{
					{
						Type: semverRangeType,
						Events: []Event{
							{Introduced: "1.0.0"},
							{LastAffected: "1.5.0"},
						},
					},
				},
			},
		},
	}

	is.Equal(fixedVersionForPurl(rec, "pkg:npm/pkg-c@1.2.0"), "")
}

func TestPurlVersion(t *testing.T) {
	is := is.New(t)

	cases := []struct {
		name string
		purl string
		want string
	}{
		{"no @", "pkg:golang/stdlib", ""},
		{"plain version", "pkg:golang/stdlib@1.25.4", "1.25.4"},
		{"qualifiers", "pkg:deb/debian/curl@1.2.3?arch=amd64", "1.2.3"},
		{"subpath", "pkg:golang/stdlib@1.25.4#internal/foo", "1.25.4"},
		{"qualifiers and subpath", "pkg:deb/debian/curl@1.2.3?arch=amd64#sub", "1.2.3"},
		{"percent-encoded plus", "pkg:generic/foo@1.2.3%2Bbuild.1", "1.2.3+build.1"},
		{"percent-encoded in qualifiers", "pkg:deb/debian/curl@1.2.3%2Bbuild?arch=amd64", "1.2.3+build"},
	}
	for _, tc := range cases {
		is.Equal(purlVersion(tc.purl), tc.want) // tc.name
	}
}

func TestRefresh_WithdrawnSkipped(t *testing.T) {
	is := is.New(t)
	purl := "pkg:npm/example@1.0.0"
	store := newFakeStore()
	osv := &fakeOSV{
		purlToRefs: map[string][]QueryRef{purl: {{ID: "VULN-1"}, {ID: "VULN-2-WITHDRAWN"}}},
		records: map[string]*Record{
			"VULN-1": {
				ID:       "VULN-1",
				Summary:  "Normal vuln",
				Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			},
			"VULN-2-WITHDRAWN": {
				ID:        "VULN-2-WITHDRAWN",
				Summary:   "Withdrawn vuln",
				Withdrawn: "2024-01-01T00:00:00Z",
			},
		},
	}
	svc := NewRefreshService(store, osv, nil)
	is.NoErr(svc.LookupPurls(context.Background(), []string{purl}))

	_, hasVuln1 := store.vulns["VULN-1"]
	is.True(hasVuln1) // normal record upserted
	_, hasWithdrawn := store.vulns["VULN-2-WITHDRAWN"]
	is.True(!hasWithdrawn) // withdrawn record must NOT be stored

	refs := store.mappings[purl]
	is.Equal(len(refs), 1)
	is.Equal(refs[0].VulnerabilityID, "VULN-1")
}

func TestRefresh_WithdrawnPreviouslyStoredRemoved(t *testing.T) {
	is := is.New(t)
	purl := "pkg:npm/example@1.0.0"
	store := newFakeStore()
	// Pre-seed: simulate a prior cycle that stored the withdrawn record.
	store.vulns["VULN-W"] = Row{ID: "VULN-W"}

	osv := &fakeOSV{
		purlToRefs: map[string][]QueryRef{purl: {{ID: "VULN-W"}}},
		records: map[string]*Record{
			"VULN-W": {
				ID:        "VULN-W",
				Summary:   "Now withdrawn",
				Withdrawn: "2024-06-01T00:00:00Z",
			},
		},
	}
	svc := NewRefreshService(store, osv, nil)
	is.NoErr(svc.LookupPurls(context.Background(), []string{purl}))

	_, stillPresent := store.vulns["VULN-W"]
	is.True(!stillPresent) // DeleteVulnerabilityByID must have removed it

	is.Equal(len(store.mappings[purl]), 0) // no purl mapping either
}

// TestIncrementalRefreshApkIncludedWhenWolfiAdvanced verifies that apk purls are included
// in a refresh cycle when the Wolfi CSV advances even if the Alpine CSV has not changed.
func TestIncrementalRefreshApkIncludedWhenWolfiAdvanced(t *testing.T) {
	is := is.New(t)

	purl := "pkg:apk/wolfi/curl@7.88.1"
	store := newFakeStore(purl)

	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	advanced := base.Add(time.Hour)

	// Alpine and Chainguard unchanged; Wolfi advanced.
	store.ecosystemState = map[string]time.Time{
		"Alpine":     base,
		"Wolfi":      base,
		"Chainguard": base,
	}
	csv := &fakeCSVFetcher{
		times: map[string]time.Time{
			"Alpine":     base,     // same as stored — not changed
			"Wolfi":      advanced, // newer than stored — triggers refresh
			"Chainguard": base,     // same as stored — not changed
		},
	}

	osv := &fakeOSV{purlToRefs: map[string][]QueryRef{purl: {}}}
	svc := NewRefreshService(store, osv, nil, WithCSVFetcher(csv))
	is.NoErr(svc.Refresh(context.Background()))

	// apk purl must have been included (QueryPurls received it).
	// We can verify indirectly: ReplacePackageVulns is called for included purls.
	_, queried := store.mappings[purl]
	is.True(queried) // apk purl must be in the refresh set when Wolfi advances

	// Wolfi state must be upserted; Alpine must not (it did not advance).
	_, alpineUpserted := store.upsertedEcos["Alpine"]
	is.True(!alpineUpserted)
	wolfiTime, wolfiUpserted := store.upsertedEcos["Wolfi"]
	is.True(wolfiUpserted)
	is.Equal(wolfiTime, advanced)
}

// TestIncrementalRefreshApkSkippedWhenAllEcosystemsUnchanged verifies that apk purls are
// excluded when all three ecosystems (Alpine, Wolfi, Chainguard) report no CSV change.
func TestIncrementalRefreshApkSkippedWhenAllEcosystemsUnchanged(t *testing.T) {
	is := is.New(t)

	purl := "pkg:apk/alpine/musl@1.2.4"
	store := newFakeStore(purl)

	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	store.ecosystemState = map[string]time.Time{
		"Alpine":     base,
		"Wolfi":      base,
		"Chainguard": base,
	}
	csv := &fakeCSVFetcher{
		times: map[string]time.Time{
			"Alpine":     base,
			"Wolfi":      base,
			"Chainguard": base,
		},
	}

	osv := &fakeOSV{purlToRefs: map[string][]QueryRef{}}
	svc := NewRefreshService(store, osv, nil, WithCSVFetcher(csv))
	is.NoErr(svc.Refresh(context.Background()))

	// No purl was queried and no ecosystem state was updated.
	_, queried := store.mappings[purl]
	is.True(!queried)
	is.Equal(len(store.upsertedEcos), 0)
	is.True(store.refreshed) // MarkRefreshed still called
}

func TestFixedVersionForPurlFiltersAffectedByPackage(t *testing.T) {
	is := is.New(t)

	npmA := AffectedPackage{Purl: "pkg:npm/pkg-a"}
	npmB := AffectedPackage{Purl: "pkg:npm/pkg-b"}

	tests := []struct {
		name     string
		rec      *Record
		purl     string
		expected string
	}{
		{
			name: "single-package match returns fixed version",
			rec: &Record{
				ID:       "GHSA-single",
				Affected: []Affected{{Package: npmA, Ranges: []Range{{Events: []Event{{Fixed: "2.0.0"}}}}}},
			},
			purl:     "pkg:npm/pkg-a@1.5.0",
			expected: "2.0.0",
		},
		{
			name: "multi-package advisory returns only the matching package fixed version",
			rec: &Record{
				ID: "GHSA-multi",
				Affected: []Affected{
					{Package: npmA, Ranges: []Range{{Events: []Event{{Fixed: "1.0.0"}}}}},
					{Package: npmB, Ranges: []Range{{Events: []Event{{Fixed: "2.0.0"}}}}},
				},
			},
			purl:     "pkg:npm/pkg-b@1.5.0",
			expected: "2.0.0",
		},
		{
			name: "multi-package advisory no match returns empty",
			rec: &Record{
				ID: "GHSA-multi",
				Affected: []Affected{
					{Package: npmA, Ranges: []Range{{Events: []Event{{Fixed: "1.0.0"}}}}},
					{Package: npmB, Ranges: []Range{{Events: []Event{{Fixed: "2.0.0"}}}}},
				},
			},
			purl:     "pkg:npm/pkg-c@1.5.0",
			expected: "",
		},
		{
			name: "no Package.Purl on any affected entry returns empty",
			rec: &Record{
				ID:       "GO-2024-1234",
				Affected: []Affected{{Ranges: []Range{{Events: []Event{{Fixed: "1.0.0"}}}}}},
			},
			purl:     "pkg:golang/github.com/example/lib@0.9.0",
			expected: "",
		},
		{
			name: "SEMVER range within matched entry is applied",
			rec: &Record{
				ID: "GHSA-semver",
				Affected: []Affected{
					{
						Package: npmA,
						Ranges: []Range{{
							Type: semverRangeType,
							Events: []Event{
								{Introduced: "0"},
								{Fixed: "1.2.0"},
								{Introduced: "2.0.0"},
								{Fixed: "2.1.0"},
							},
						}},
					},
					{Package: npmB, Ranges: []Range{{Events: []Event{{Fixed: "3.0.0"}}}}},
				},
			},
			purl:     "pkg:npm/pkg-a@2.0.5",
			expected: "2.1.0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(fixedVersionForPurl(tc.rec, tc.purl), tc.expected)
		})
	}
}

// TestHydrateSkipsUnchangedRecords asserts the acceptance criterion for
// ocidex-0le.8: when all vuln records are unchanged (stored modified_at ==
// querybatch Modified), zero GetVuln network calls are made and purl mappings
// remain correct.
func TestHydrateSkipsUnchangedRecords(t *testing.T) {
	is := is.New(t)

	const (
		purlA = "pkg:npm/a@1.0.0"
		purlB = "pkg:npm/b@2.0.0"
		modA  = "2025-01-15T10:00:00Z"
		modB  = "2025-02-20T12:30:00Z"
	)

	// Build two Records with a fixed version derivable from their Affected arrays.
	// Package.Purl must be version-stripped (purlBase) for filteredAffected to match.
	recCVE1 := &Record{
		ID: "CVE-2025-0001",
		Affected: []Affected{
			{
				Package: AffectedPackage{Purl: "pkg:npm/a"},
				Ranges: []Range{{
					Events: []Event{{Introduced: "1.0.0"}, {Fixed: "1.0.5"}},
				}},
			},
		},
	}
	recCVE2 := &Record{
		ID: "CVE-2025-0002",
		Affected: []Affected{
			{
				Package: AffectedPackage{Purl: "pkg:npm/b"},
				Ranges: []Range{{
					Events: []Event{{Introduced: "2.0.0"}, {Fixed: "2.1.0"}},
				}},
			},
		},
	}

	rawCVE1, err := json.Marshal(recCVE1)
	is.NoErr(err)
	rawCVE2, err := json.Marshal(recCVE2)
	is.NoErr(err)

	modTimeCVE1, _ := time.Parse(time.RFC3339, modA)
	modTimeCVE2, _ := time.Parse(time.RFC3339, modB)

	store := newFakeStore(purlA, purlB)
	store.storedModifiedAts["CVE-2025-0001"] = modTimeCVE1
	store.storedModifiedAts["CVE-2025-0002"] = modTimeCVE2
	store.storedRaw["CVE-2025-0001"] = json.RawMessage(rawCVE1)
	store.storedRaw["CVE-2025-0002"] = json.RawMessage(rawCVE2)

	osv := &fakeOSV{
		purlToRefs: map[string][]QueryRef{
			purlA: {{ID: "CVE-2025-0001", Modified: modA}},
			purlB: {{ID: "CVE-2025-0002", Modified: modB}},
		},
		// records intentionally empty — GetVuln must NOT be called
	}

	svc := NewRefreshService(store, osv, nil)
	is.NoErr(svc.Refresh(context.Background()))

	// Zero network calls were made.
	is.Equal(len(osv.getCalls), 0)

	// Purl mappings are populated with correct fixed versions.
	is.True(len(store.mappings[purlA]) == 1)
	is.Equal(store.mappings[purlA][0].VulnerabilityID, "CVE-2025-0001")
	is.Equal(store.mappings[purlA][0].FixedVersion, "1.0.5")

	is.True(len(store.mappings[purlB]) == 1)
	is.Equal(store.mappings[purlB][0].VulnerabilityID, "CVE-2025-0002")
	is.Equal(store.mappings[purlB][0].FixedVersion, "2.1.0")
}
