package grypematch

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/vuln"
)

// fakeStore is an in-memory Store.
type fakeStore struct {
	docs        []vuln.SBOMDoc
	matched     map[pgtype.UUID]time.Time
	builtStored *time.Time
	purls       []string
	vulns       map[string]vuln.Row
	mappings    map[string][]vuln.PackageVulnRef
	fullWrites  int // ReplacePackageVulns calls
}

func newFakeStore(docs ...vuln.SBOMDoc) *fakeStore {
	return &fakeStore{
		docs: docs, matched: map[pgtype.UUID]time.Time{},
		vulns: map[string]vuln.Row{}, mappings: map[string][]vuln.PackageVulnRef{},
	}
}

func (s *fakeStore) ListSBOMsToMatch(_ context.Context, built time.Time, all bool, after pgtype.UUID, limit int32) ([]vuln.SBOMDoc, error) {
	var out []vuln.SBOMDoc
	for _, d := range s.docs {
		if string(d.ID.Bytes[:]) <= string(after.Bytes[:]) {
			continue
		}
		if b, ok := s.matched[d.ID]; !all && ok && b.Equal(built) {
			continue
		}
		out = append(out, d)
		if len(out) == int(limit) {
			break
		}
	}
	return out, nil
}
func (s *fakeStore) MarkSBOMMatched(_ context.Context, id pgtype.UUID, built time.Time) error {
	s.matched[id] = built
	return nil
}
func (s *fakeStore) MatchedDBBuilt(context.Context) (time.Time, bool, error) {
	if s.builtStored == nil {
		return time.Time{}, false, nil
	}
	return *s.builtStored, true, nil
}
func (s *fakeStore) SetMatchedDBBuilt(_ context.Context, b time.Time) error {
	s.builtStored = &b
	return nil
}
func (s *fakeStore) ListDistinctComponentPurls(context.Context) ([]string, error) {
	return s.purls, nil
}
func (s *fakeStore) UpsertVulnerability(_ context.Context, v vuln.Row) error {
	s.vulns[v.ID] = v
	return nil
}
func (s *fakeStore) InsertVulnerabilityIfAbsent(_ context.Context, v vuln.Row) (bool, error) {
	if _, ok := s.vulns[v.ID]; ok {
		return false, nil
	}
	s.vulns[v.ID] = v
	return true, nil
}
func (s *fakeStore) ReplaceVulnerabilityRefs(context.Context, string, []vuln.Reference) error {
	return nil
}
func (s *fakeStore) ReplacePackageVulns(_ context.Context, purl string, refs []vuln.PackageVulnRef) error {
	s.fullWrites++
	if len(refs) == 0 {
		delete(s.mappings, purl)
		return nil
	}
	s.mappings[purl] = refs
	return nil
}
func (s *fakeStore) AddPackageVulns(_ context.Context, purl string, refs []vuln.PackageVulnRef) error {
	s.mappings[purl] = append(s.mappings[purl], refs...)
	return nil
}
func (s *fakeStore) PruneOrphanVulnerabilities(context.Context) (int64, error) {
	used := map[string]bool{}
	for _, refs := range s.mappings {
		for _, r := range refs {
			used[r.VulnerabilityID] = true
		}
	}
	var n int64
	for id := range s.vulns {
		if !used[id] {
			delete(s.vulns, id)
			n++
		}
	}
	return n, nil
}

// fakeDB serves a fixed matcher and build, optionally failing Refresh.
type fakeDB struct {
	m       *Matcher
	built   time.Time
	fail    bool
	refresh int
}

func (d *fakeDB) Refresh() (bool, error) {
	d.refresh++
	if d.fail {
		return false, errors.New("listing unreachable")
	}
	return false, nil
}
func (d *fakeDB) Matcher() (*Matcher, time.Time) { return d.m, d.built }

func uuidN(n byte) pgtype.UUID {
	var u pgtype.UUID
	u.Bytes[15] = n
	u.Valid = true
	return u
}

func requestsDoc(t *testing.T, id byte, ver string) vuln.SBOMDoc {
	return vuln.SBOMDoc{ID: uuidN(id), Raw: cdxDoc(t, lib("requests", ver, "pkg:pypi/requests@"+ver))}
}

var requestsVuln = vulnerability.Vulnerability{
	Reference:   ref("GHSA-9wx4-h78v-vm56", "github:language:python"),
	PackageName: "requests",
	Constraint:  version.MustGetConstraint("< 2.32.0", version.PythonFormat),
	Fix:         vulnerability.Fix{Versions: []string{"2.32.0"}, State: vulnerability.FixStateFixed},
	Metadata:    &vulnerability.Metadata{Severity: "Medium"},
}

func keys[M ~map[string]V, V any](m M) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestRefresherFullRematch(t *testing.T) {
	is := is.New(t)
	day1 := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	store := newFakeStore(requestsDoc(t, 1, "2.31.0"), requestsDoc(t, 2, "2.32.0"))
	store.purls = []string{"pkg:pypi/requests@2.31.0", "pkg:pypi/requests@2.32.0", "pkg:pypi/stale@1"}
	// A mapping and row left over from the OSV era, for a purl that no longer matches.
	store.mappings["pkg:pypi/stale@1"] = []vuln.PackageVulnRef{{VulnerabilityID: "PYSEC-OLD"}}
	store.vulns["PYSEC-OLD"] = vuln.Row{ID: "PYSEC-OLD"}

	db := &fakeDB{m: NewMatcher(mock.VulnerabilityProvider(requestsVuln)), built: day1}
	r := newRefresher(db, store, time.Hour, nil)
	is.NoErr(r.Step(context.Background()))

	is.Equal(keys(store.mappings), []string{"pkg:pypi/requests@2.31.0"}) // stale purl emptied
	is.Equal(store.mappings["pkg:pypi/requests@2.31.0"][0].FixedVersion, "2.32.0")
	is.Equal(keys(store.vulns), []string{"GHSA-9wx4-h78v-vm56"}) // orphan pruned
	is.Equal(store.vulns["GHSA-9wx4-h78v-vm56"].Severity, vuln.SeverityMedium)
	is.True(store.builtStored != nil && store.builtStored.Equal(day1))
	is.Equal(len(store.matched), 2)

	// Same build again: nothing pending, so no full rebuild.
	writes := store.fullWrites
	is.NoErr(r.Step(context.Background()))
	is.Equal(store.fullWrites, writes)
}

func TestRefresherIncrementalAddsNewSBOMOnly(t *testing.T) {
	is := is.New(t)
	day1 := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	store := newFakeStore(requestsDoc(t, 1, "2.32.0"))
	db := &fakeDB{m: NewMatcher(mock.VulnerabilityProvider(requestsVuln)), built: day1}
	r := newRefresher(db, store, time.Hour, nil)
	is.NoErr(r.Step(context.Background())) // full re-match: nothing vulnerable
	is.Equal(len(store.mappings), 0)

	store.vulns["GHSA-9wx4-h78v-vm56"] = vuln.Row{ID: "GHSA-9wx4-h78v-vm56", Severity: vuln.SeverityCritical}
	store.docs = append(store.docs, requestsDoc(t, 2, "2.31.0")) // newly ingested
	writes := store.fullWrites
	is.NoErr(r.Step(context.Background()))

	is.Equal(store.fullWrites, writes) // incremental: no replace-all
	is.Equal(keys(store.mappings), []string{"pkg:pypi/requests@2.31.0"})
	// The existing row (derived by a full re-match) is not overwritten by one SBOM's view.
	is.Equal(store.vulns["GHSA-9wx4-h78v-vm56"].Severity, vuln.SeverityCritical)
	is.Equal(store.matched[uuidN(2)], day1)
}

func TestRefresherNewBuildTriggersFullRematch(t *testing.T) {
	is := is.New(t)
	day1 := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	store := newFakeStore(requestsDoc(t, 1, "2.31.0"))
	db := &fakeDB{m: NewMatcher(mock.VulnerabilityProvider()), built: day1}
	r := newRefresher(db, store, time.Hour, nil)
	is.NoErr(r.Step(context.Background()))
	is.Equal(len(store.mappings), 0) // day1 knows no vulnerabilities

	// The next build discloses one: every SBOM is re-matched, no re-ingest.
	db.m, db.built = NewMatcher(mock.VulnerabilityProvider(requestsVuln)), day1.Add(24*time.Hour)
	is.NoErr(r.Step(context.Background()))
	is.Equal(keys(store.mappings), []string{"pkg:pypi/requests@2.31.0"})
	is.True(store.builtStored.Equal(db.built))
}

func TestRefresherDBCheckBackoff(t *testing.T) {
	is := is.New(t)
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	db := &fakeDB{built: now, fail: true}
	r := newRefresher(db, newFakeStore(), time.Hour, nil)
	r.now = func() time.Time { return now }

	err := r.Step(context.Background())
	is.True(err != nil) // no database yet
	is.Equal(db.refresh, 1)

	now = now.Add(time.Minute)
	_ = r.Step(context.Background())
	is.Equal(db.refresh, 1) // inside the 5m backoff: not re-checked

	now = now.Add(5 * time.Minute)
	_ = r.Step(context.Background())
	is.Equal(db.refresh, 2)
	is.Equal(r.backoff, 10*time.Minute) // doubled

	db.fail = false
	db.m = NewMatcher(mock.VulnerabilityProvider())
	now = now.Add(10 * time.Minute)
	is.NoErr(r.Step(context.Background()))
	is.Equal(r.backoff, time.Duration(0))
	is.Equal(r.nextCheck, now.Add(time.Hour)) // back on the regular interval
}

func TestPrepareAppliesMainModuleVersion(t *testing.T) {
	is := is.New(t)
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
		"metadata":{"properties":[{"name":"syft:image:labels:org.opencontainers.image.source","value":"https://github.com/fluxcd/kustomize-controller"}]},
		"components":[{"type":"library","name":"github.com/fluxcd/kustomize-controller","version":"UNKNOWN",
		"purl":"pkg:golang/github.com/fluxcd/kustomize-controller"}]}`)
	out := prepare(vuln.SBOMDoc{Raw: raw, SubjectVersion: "v1.9.5"})
	is.True(string(out) != string(raw))
	is.True(strings.Contains(string(out), `"pkg:golang/github.com/fluxcd/kustomize-controller@v1.9.5"`))

	is.Equal(string(prepare(vuln.SBOMDoc{Raw: raw})), string(raw))                         // no subject version
	is.Equal(string(prepare(vuln.SBOMDoc{Raw: []byte("{}"), SubjectVersion: "v1"})), "{}") // not CycloneDX
}
