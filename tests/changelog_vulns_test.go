package tests

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"
)

type changeVulnJSON struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
}

// labels renders vulns as "ID SEVERITY", nil when there are none.
func labels(vs []changeVulnJSON) []string {
	if len(vs) == 0 {
		return nil
	}
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.ID+" "+v.Severity)
	}
	return out
}

type changelogVulnPage struct {
	Entries []struct {
		Changes []struct {
			Name   string           `json:"name"`
			Type   string           `json:"type"`
			Closes []changeVulnJSON `json:"closes"`
			Opens  []changeVulnJSON `json:"opens"`
		} `json:"changes"`
		Vulns *struct {
			Closed map[string]int `json:"closed"`
			Opened map[string]int `json:"opened"`
		} `json:"vulns"`
	} `json:"entries"`
}

// seedChangelogSBOM inserts one version of an artifact carrying the given
// packages, each a (name, version, purl) triple.
func seedChangelogSBOM(t *testing.T, pool *pgxpool.Pool, nsID string, artifactID pgtype.UUID, version string, created time.Time, pkgs ...[3]string) {
	t.Helper()
	ctx := t.Context()
	var sbomID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO sbom (spec_version, raw_bom, artifact_id, namespace_id, subject_version, created_at)
		VALUES ('1.6', '{}'::jsonb, $1, $2::uuid, $3, $4) RETURNING id::text
	`, artifactID, nsID, version, created).Scan(&sbomID); err != nil {
		t.Fatalf("seed sbom %s: %v", version, err)
	}
	for _, p := range pkgs {
		if _, err := pool.Exec(ctx, `
			INSERT INTO component (sbom_id, type, name, version, purl)
			VALUES ($1::uuid, 'library', $2, $3, $4)
		`, sbomID, p[0], p[1], p[2]); err != nil {
			t.Fatalf("seed component %s: %v", p[0], err)
		}
	}
}

// TestArtifactChangelogVulns covers what each package change does to its own
// CVEs and what the release does to the image's: a CVE the upgraded package
// drops but another package still carries is closed for that package and not
// for the image.
func TestArtifactChangelogVulns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)

	owner := seedUser(t, pool, 9401, "changelog-vuln-owner", "member")
	nsID := seedNamespace(t, pool, "changelog-vuln-ns", owner, "public")
	art := seedBlastArtifact(t, pool, "docker.io/changelog-vulns")

	now := time.Now()
	seedChangelogSBOM(t, pool, nsID, art, "1.0.0", now.Add(-2*time.Hour),
		[3]string{"liba", "1.0.0", "pkg:generic/liba@1.0.0"},
		[3]string{"libb", "1.0.0", "pkg:generic/libb@1.0.0"},
		[3]string{"libc", "1.0.0", "pkg:generic/libc@1.0.0"},
	)
	seedChangelogSBOM(t, pool, nsID, art, "1.1.0", now.Add(-time.Hour),
		[3]string{"liba", "2.0.0", "pkg:generic/liba@2.0.0"},
		[3]string{"libb", "1.0.0", "pkg:generic/libb@1.0.0"},
		[3]string{"libe", "1.0.0", "pkg:generic/libe@1.0.0"},
	)

	seedAdvisory(t, pool, "CVE-2031-0001", "CVE-2031-0001", "CRITICAL", 9.8, "pkg:generic/liba@1.0.0")
	seedAdvisory(t, pool, "CVE-2031-0002", "CVE-2031-0002", "HIGH", 7.5, "pkg:generic/liba@1.0.0")
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO package_vulnerability (purl, vulnerability_id) VALUES ('pkg:generic/libb@1.0.0', 'CVE-2031-0002')`); err != nil {
		t.Fatal(err)
	}
	seedAdvisory(t, pool, "CVE-2031-0003", "CVE-2031-0003", "LOW", 2.0, "pkg:generic/libc@1.0.0")
	seedAdvisory(t, pool, "CVE-2031-0004", "CVE-2031-0004", "MEDIUM", 5.0, "pkg:generic/liba@2.0.0")
	seedAdvisory(t, pool, "CVE-2031-0005", "CVE-2031-0005", "LOW", 3.0, "pkg:generic/libe@1.0.0")

	srv, _ := setupServerWithAuth(t, pool)
	defer srv.Close()
	resp, err := doWithAuth(t, http.MethodGet, srv.URL+"/api/v1/artifacts/"+art.String()+"/changelog", "", "")
	is.NoErr(err)
	defer resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusOK)
	var page changelogVulnPage
	is.NoErr(json.NewDecoder(resp.Body).Decode(&page))

	is.Equal(len(page.Entries), 1)
	e := page.Entries[0]
	type vulns = []string
	got := map[string][2]vulns{}
	for _, c := range e.Changes {
		got[c.Type+" "+c.Name] = [2]vulns{labels(c.Closes), labels(c.Opens)}
	}
	is.Equal(got, map[string][2]vulns{
		"modified liba": {{"CVE-2031-0001 CRITICAL", "CVE-2031-0002 HIGH"}, {"CVE-2031-0004 MEDIUM"}},
		"removed libc":  {{"CVE-2031-0003 LOW"}, nil},
		"added libe":    {nil, {"CVE-2031-0005 LOW"}},
	})

	is.True(e.Vulns != nil)
	// CVE-2031-0002 is still on libb, so the image did not close it.
	is.Equal(e.Vulns.Closed, map[string]int{"critical": 1, "high": 0, "medium": 0, "low": 1, "unknown": 0})
	is.Equal(e.Vulns.Opened, map[string]int{"critical": 0, "high": 0, "medium": 1, "low": 1, "unknown": 0})
}
