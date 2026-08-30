package tests

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/vuln"
)

// The feed's contract is that it reports the three signals that already exist
// in the schema — a new sbom row, a provenance_drift_events row, and a
// component→package_vulnerability match — scoped to the watch set, and that it
// re-checks visibility even though the watchlist does not. Every case below
// pins one half of that: what gets in, and what stops getting in.

// curlPurl appears only in secondSBOM, so a vulnerability against it lands on
// the artifact's *latest* SBOM. addUserPurl (declared in vuln_integration_test)
// appears only in minimalSBOM, which makes it the control for the same rule.
const curlPurl = "pkg:deb/ubuntu/curl@8.5.0?arch=arm64&distro=ubuntu-24.04"

type feedEvent struct {
	Kind            string    `json:"kind"`
	ID              string    `json:"id"`
	OccurredAt      time.Time `json:"occurredAt"`
	ArtifactID      string    `json:"artifactId"`
	ArtifactName    string    `json:"artifactName"`
	SBOMID          string    `json:"sbomId"`
	Version         *string   `json:"version"`
	PreviousVersion *string   `json:"previousVersion"`
	NewStatus       *string   `json:"newStatus"`
	Reason          *string   `json:"reason"`
	VulnerabilityID *string   `json:"vulnerabilityId"`
	Severity        *string   `json:"severity"`
}

func watchFeed(t *testing.T, baseURL, apiKey string) []feedEvent {
	t.Helper()
	resp, err := doWithAuth(t, http.MethodGet, baseURL+"/api/v1/users/me/watches/feed", "", apiKey)
	if err != nil {
		t.Fatalf("listing watch feed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing watch feed: status %d", resp.StatusCode)
	}
	var body struct {
		Data []feedEvent `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding watch feed: %v", err)
	}
	return body.Data
}

func eventsOfKind(events []feedEvent, kind string) []feedEvent {
	out := []feedEvent{}
	for _, e := range events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// seedDrift writes a provenance_drift_events row directly. Producing one for
// real would need a registry to re-verify against, and the feed's job is to
// report the row, not to make it.
func seedDrift(t *testing.T, pool *pgxpool.Pool, sbomID string) {
	t.Helper()
	_, err := pool.Exec(t.Context(),
		`INSERT INTO provenance_drift_events (sbom_id, previous_status, new_status, reason)
		 VALUES ($1::uuid, 'verified', 'artifact_missing', 'artifact_missing')`, sbomID)
	if err != nil {
		t.Fatalf("seeding drift event: %v", err)
	}
}

func setNamespaceVisibility(t *testing.T, pool *pgxpool.Pool, namespaceID, visibility string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(),
		`UPDATE namespace SET visibility = $2 WHERE id = $1::uuid`, namespaceID, visibility); err != nil {
		t.Fatalf("setting namespace visibility: %v", err)
	}
}

func TestWatchedArtifactChangeFeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()

	is := is.New(t)
	store := vuln.NewPGStore(pool)

	watcherID := seedUser(t, pool, 7611, "feed-watcher", "member")
	watcherKey, err := authSvc.CreateAPIKey(t.Context(), watcherID, "watcher", nil)
	is.NoErr(err)
	ownerID := seedUser(t, pool, 7612, "feed-owner", "member")
	ownerKey, err := authSvc.CreateAPIKey(t.Context(), ownerID, "owner", nil)
	is.NoErr(err)

	// The watched artifact belongs to somebody else and is public, which is the
	// case the watchlist exists for.
	ns := seedNamespace(t, pool, "feed-ns", ownerID, "public")
	src := seedSource(t, pool, ns, "upload", "feed-src")
	mustIngest(t, srv.URL, "/api/v1/sboms?source="+src, minimalSBOM, ownerKey)
	// created_at is the feed's ordering key, so the two versions must not land
	// in the same instant.
	time.Sleep(100 * time.Millisecond)
	sbom2 := mustIngest(t, srv.URL, "/api/v1/sboms?source="+src, secondSBOM, ownerKey)

	artifactID := artifactIDForSource(t, pool, src)

	// A finding on the newest SBOM, and a control on a purl that only the older
	// one carries.
	seedVuln(t, store, "CVE-2099-0001", "HIGH", curlPurl)
	seedVuln(t, store, "CVE-2099-0002", "LOW", addUserPurl)
	seedDrift(t, pool, sbom2)

	resp, err := doWithAuth(t, http.MethodPut, srv.URL+"/api/v1/users/me/watches/"+artifactID, "", watcherKey)
	is.NoErr(err)
	resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusNoContent)

	t.Run("reports all three signals for a watched artifact", func(t *testing.T) {
		is := is.New(t)
		events := watchFeed(t, srv.URL, watcherKey)

		versions := eventsOfKind(events, "new_version")
		is.Equal(len(versions), 2)
		drift := eventsOfKind(events, "drift")
		is.Equal(len(drift), 1)
		is.Equal(*drift[0].NewStatus, "artifact_missing")
		is.Equal(*drift[0].Reason, "artifact_missing")
		is.Equal(drift[0].SBOMID, sbom2)

		vulns := eventsOfKind(events, "vulnerability")
		// Only the newest SBOM is scanned: CVE-2099-0002 matches a purl that
		// exists solely in the superseded version, so it is not news.
		is.Equal(len(vulns), 1)
		is.Equal(*vulns[0].VulnerabilityID, "CVE-2099-0001")
		is.Equal(*vulns[0].Severity, "HIGH")

		for _, e := range events {
			is.Equal(e.ArtifactID, artifactID)
			is.True(e.ArtifactName != "")
		}
	})

	t.Run("is ordered newest first", func(t *testing.T) {
		is := is.New(t)
		events := watchFeed(t, srv.URL, watcherKey)
		is.True(len(events) > 1)
		for i := 1; i < len(events); i++ {
			if events[i].OccurredAt.After(events[i-1].OccurredAt) {
				t.Fatalf("event %d (%s) is newer than the one before it", i, events[i].Kind)
			}
		}
	})

	t.Run("version events link to their predecessor", func(t *testing.T) {
		is := is.New(t)
		versions := eventsOfKind(watchFeed(t, srv.URL, watcherKey), "new_version")
		is.Equal(len(versions), 2)

		// Newest first, so the second version comes first and is the one with a
		// predecessor to diff against; the artifact's first version has none.
		is.Equal(*versions[0].Version, "24.04.1")
		is.True(versions[0].PreviousVersion != nil)
		is.Equal(*versions[0].PreviousVersion, "24.04")
		is.Equal(*versions[1].Version, "24.04")
		is.True(versions[1].PreviousVersion == nil)
	})

	t.Run("is self-scoped", func(t *testing.T) {
		is := is.New(t)
		// The owner of the artifact watches nothing, so owning the events is
		// not enough to receive them.
		is.Equal(len(watchFeed(t, srv.URL, ownerKey)), 0)
	})

	t.Run("a since-privatised artifact drops out but stays watched", func(t *testing.T) {
		is := is.New(t)
		setNamespaceVisibility(t, pool, ns, "private")
		defer setNamespaceVisibility(t, pool, ns, "public")

		// The events are content the watcher may no longer see.
		is.Equal(len(watchFeed(t, srv.URL, watcherKey)), 0)
		// The watch is the watcher's own bookmark, so it survives — otherwise a
		// star would vanish with no way to notice or clear it.
		is.Equal(watchIDs(t, srv.URL, watcherKey), []string{artifactID})
		// The owner still sees their own artifact's events... once they watch it.
		is.Equal(len(watchFeed(t, srv.URL, ownerKey)), 0)
	})

	t.Run("anonymous callers are rejected", func(t *testing.T) {
		is := is.New(t)
		resp, err := doWithAuth(t, http.MethodGet, srv.URL+"/api/v1/users/me/watches/feed", "", "")
		is.NoErr(err)
		resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusUnauthorized)
	})
}
