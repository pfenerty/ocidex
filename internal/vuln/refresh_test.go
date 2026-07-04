package vuln

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

var errFakeUpsert = errors.New("simulated upsert failure")

// fakeOSV is an in-memory OSVQuerier.
type fakeOSV struct {
	purlToIDs map[string][]string
	records   map[string]*Record
	getCalls  map[string]int
}

func (f *fakeOSV) QueryPurls(_ context.Context, purls []string) (map[string][]string, error) {
	out := make(map[string][]string, len(purls))
	for _, p := range purls {
		out[p] = f.purlToIDs[p]
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
	purls          []string
	vulns          map[string]Row
	mappings       map[string][]PackageVulnRef
	upsertErr      map[string]error // per-vuln-ID upsert failure to simulate bad records
	refreshed      bool
	last           time.Time
	lastOK         bool
	ecosystemState map[string]time.Time // ecosystem → stored last_modified_at
	upsertedEcos   map[string]time.Time // ecosystem → value written by UpsertEcosystemState
}

func newFakeStore(purls ...string) *fakeStore {
	return &fakeStore{
		purls:          purls,
		vulns:          map[string]Row{},
		mappings:       map[string][]PackageVulnRef{},
		ecosystemState: map[string]time.Time{},
		upsertedEcos:   map[string]time.Time{},
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

func (s *fakeStore) UpsertVulnerability(_ context.Context, v Row) error {
	if err := s.upsertErr[v.ID]; err != nil {
		return err
	}
	s.vulns[v.ID] = v
	return nil
}
func (s *fakeStore) ReplacePackageVulns(_ context.Context, purl string, refs []PackageVulnRef) error {
	s.mappings[purl] = refs
	return nil
}
func (s *fakeStore) ListUnknownPurlsForSBOM(_ context.Context, _ pgtype.UUID) ([]string, error) {
	return nil, nil
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
		purlToIDs: map[string][]string{
			"pkg:npm/a@1.0.0": {"CVE-1", "CVE-2"},
			"pkg:npm/b@1.0.0": {"CVE-1"}, // shares CVE-1 with a
			"pkg:npm/c@1.0.0": {},        // clean
		},
		records: map[string]*Record{
			"CVE-1": {
				ID:       "CVE-1",
				Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
				Affected: []Affected{{Ranges: []Range{{Events: []Event{{Fixed: "1.0.1"}}}}}},
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
		purlToIDs: map[string][]string{
			"pkg:npm/a@1.0.0": {"CVE-GOOD", "RHSA-BAD"}, // one good, one that fails to store
			"pkg:npm/b@1.0.0": {"CVE-GOOD"},
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
	svc := NewRefreshService(store, &fakeOSV{}, nil)
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
	osv := &fakeOSV{purlToIDs: map[string][]string{}}

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
		purlToIDs: map[string][]string{
			"pkg:npm/a@1.0.0": {"CVE-1"},
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
		purlToIDs: map[string][]string{"pkg:npm/a@1.0.0": {"CVE-1"}},
		records:   map[string]*Record{"CVE-1": {ID: "CVE-1"}},
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
		purlToIDs: map[string][]string{"pkg:oci/myimage@sha256:abc": {}},
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

	// Truly unknown (no CVSS, no database_specific) still returns UNKNOWN.
	unknown := &Record{ID: "GO-2024-0004"}
	row = toRow(unknown)
	is.Equal(row.Severity, SeverityUnknown)
}
