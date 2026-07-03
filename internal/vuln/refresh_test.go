package vuln

import (
	"context"
	"testing"
	"time"

	"github.com/matryer/is"
)

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
	purls     []string
	vulns     map[string]Row
	mappings  map[string][]PackageVulnRef
	refreshed bool
	last      time.Time
	lastOK    bool
}

func newFakeStore(purls ...string) *fakeStore {
	return &fakeStore{purls: purls, vulns: map[string]Row{}, mappings: map[string][]PackageVulnRef{}}
}

func (s *fakeStore) ListDistinctComponentPurls(context.Context) ([]string, error) {
	return s.purls, nil
}
func (s *fakeStore) UpsertVulnerability(_ context.Context, v Row) error {
	s.vulns[v.ID] = v
	return nil
}
func (s *fakeStore) ReplacePackageVulns(_ context.Context, purl string, refs []PackageVulnRef) error {
	s.mappings[purl] = refs
	return nil
}
func (s *fakeStore) LastRefreshedAt(context.Context) (time.Time, bool, error) {
	return s.last, s.lastOK, nil
}
func (s *fakeStore) MarkRefreshed(context.Context) error {
	s.refreshed = true
	return nil
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
