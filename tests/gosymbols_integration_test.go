package tests

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/grype/grype/pkg/qualifier"
	qgosymbols "github.com/anchore/grype/grype/pkg/qualifier/gosymbols"
	grypeversion "github.com/anchore/grype/grype/version"
	grypevuln "github.com/anchore/grype/grype/vulnerability"
	grypemock "github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/gosymbols"
	"github.com/pfenerty/ocidex/internal/vuln"
	"github.com/pfenerty/ocidex/internal/vuln/grypematch"
)

const goStdlibPurl = "pkg:golang/stdlib@1.18.2"

// goBinarySBOM is a container SBOM holding one Go binary whose standard-library
// component carries the ocidex symbol properties (ADR-050).
func goBinarySBOM(t *testing.T, serial string, digestHex byte, syms gosymbols.Table) string {
	t.Helper()
	props := make([]cdx.Property, 0, 6+len(syms))
	props = append(props, []cdx.Property{
		{Name: "syft:package:foundBy", Value: "go-module-binary-cataloger"},
		{Name: "syft:package:language", Value: "go"},
		{Name: "syft:package:type", Value: "go-module"},
		{Name: "syft:package:metadataType", Value: "go-module-buildinfo-entry"},
		{Name: "syft:location:0:path", Value: "/usr/local/bin/gosu"},
		{Name: "syft:metadata:goCompiledVersion", Value: "go1.18.2"},
	}...)
	props = append(props, gosymbols.Properties(syms)...)
	digest := "sha256:" + strings.Repeat(string(digestHex), 64)
	bom := map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"serialNumber": "urn:uuid:" + serial,
		"metadata": map[string]any{"component": map[string]any{
			"type": "container", "name": "docker.io/acme/gosu@" + digest, "version": "1.0",
			"properties": []map[string]string{
				{"name": "syft:image:labels:org.opencontainers.image.architecture", "value": "amd64"},
				{"name": "syft:image:labels:org.opencontainers.image.created", "value": "2024-01-01T00:00:00Z"},
			},
		}},
		"components": []map[string]any{{
			"type": "library", "name": "stdlib", "version": "go1.18.2", "purl": goStdlibPurl,
			"properties": props,
		}},
	}
	b, err := json.Marshal(bom)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestGoSymbolsIngestAndMatch covers ADR-050 end to end on real Postgres:
// symbols carried by CycloneDX are stored once in deduplicated sets (two SBOMs
// with the same module build share one), stripped from raw_bom, queryable across
// SBOMs, and used by the matcher to drop advisories whose vulnerable symbols are
// not linked.
func TestGoSymbolsIngestAndMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()
	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()
	is := is.New(t)

	memberID := seedUser(t, pool, 8013, "gosymbols-member", "member")
	memberKey, err := authSvc.CreateAPIKey(t.Context(), memberID, "gosymbols-test", nil)
	is.NoErr(err)

	serving := gosymbols.Table{"net/http": {"(*Server).Serve", "Get"}, "unsafe": {}}
	clientOnly := gosymbols.Table{"net/http": {"Get"}}
	a := mustIngest(t, srv.URL, ingestPath(t, pool, memberID),
		goBinarySBOM(t, "aaaaaaaa-0000-0000-0000-000000000001", 'a', serving), memberKey)
	b := mustIngest(t, srv.URL, ingestPath(t, pool, memberID),
		goBinarySBOM(t, "aaaaaaaa-0000-0000-0000-000000000002", 'b', serving), memberKey)
	c := mustIngest(t, srv.URL, ingestPath(t, pool, memberID),
		goBinarySBOM(t, "aaaaaaaa-0000-0000-0000-000000000003", 'c', clientOnly), memberKey)

	// Two distinct symbol lists → two sets, though three components link them.
	var sets, linked int
	is.NoErr(pool.QueryRow(t.Context(), "SELECT count(*) FROM go_symbol_set").Scan(&sets))
	is.NoErr(pool.QueryRow(t.Context(), "SELECT count(*) FROM component WHERE go_symbol_set_id IS NOT NULL").Scan(&linked))
	is.Equal(sets, 2)
	is.Equal(linked, 3)

	// Names are stored normalized, once.
	var serveRows int
	is.NoErr(pool.QueryRow(t.Context(), `SELECT count(*) FROM go_symbol s JOIN go_package p ON p.id = s.package_id
		WHERE p.import_path = 'net/http' AND s.name = 'Server.Serve'`).Scan(&serveRows))
	is.Equal(serveRows, 1)

	// Symbols live in the tables, not also in raw_bom.
	var raw string
	is.NoErr(pool.QueryRow(t.Context(), "SELECT raw_bom::text FROM sbom WHERE id = $1", a).Scan(&raw))
	is.True(!strings.Contains(raw, gosymbols.PropertyPrefix))
	is.True(strings.Contains(raw, "syft:location:0:path")) // the rest of the document is intact

	// Correlation across SBOMs: which SBOMs link net/http.Server.Serve? (GIN containment)
	rows, err := pool.Query(t.Context(), `
		SELECT DISTINCT c.sbom_id::text FROM component c
		JOIN go_symbol_set gs ON gs.id = c.go_symbol_set_id
		WHERE gs.symbol_ids @> ARRAY[(SELECT s.id FROM go_symbol s JOIN go_package p ON p.id = s.package_id
		                             WHERE p.import_path = 'net/http' AND s.name = 'Server.Serve')]
		ORDER BY 1`)
	is.NoErr(err)
	var linking []string
	for rows.Next() {
		var id string
		is.NoErr(rows.Scan(&id))
		linking = append(linking, id)
	}
	rows.Close()
	want := []string{a, b}
	if want[0] > want[1] {
		want[0], want[1] = want[1], want[0]
	}
	is.Equal(linking, want)

	// The store hands the matcher the symbols keyed by purl and binary path.
	store := vuln.NewPGStore(pool)
	var aID pgtype.UUID
	is.NoErr(aID.Scan(a))
	syms, err := store.SBOMGoSymbols(t.Context(), aID)
	is.NoErr(err)
	tbl := syms[vuln.GoSymbolKey{Purl: goStdlibPurl, FilePath: "/usr/local/bin/gosu"}].Symbols
	is.Equal(tbl["net/http"], []string{"Get", "Server.Serve"})
	is.True(tbl["unsafe"] != nil && len(tbl["unsafe"]) == 0) // present, no symbols

	// Matching: the advisory is scoped to net/http.Server.Serve, so only the SBOMs
	// that link it are affected.
	adv := grypevuln.Vulnerability{
		Reference:   grypevuln.Reference{ID: "GO-2023-1703", Namespace: "govulndb:language:go"},
		PackageName: "stdlib",
		Constraint:  grypeversion.MustGetConstraint("< 1.19.8", grypeversion.GolangFormat),
		Fix:         grypevuln.Fix{Versions: []string{"1.19.8"}, State: grypevuln.FixStateFixed},
		PackageQualifiers: []qualifier.Qualifier{
			qgosymbols.New([]qgosymbols.Import{{Path: "net/http", Symbols: []string{"Server.Serve"}}}),
		},
		Metadata: &grypevuln.Metadata{Severity: "High"},
	}
	db := grypematch.NewFixedDB(grypemock.VulnerabilityProvider(adv), time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), nil)
	is.NoErr(grypematch.NewRefresher(db, store, time.Hour, nil).Step(t.Context()))

	vulnCount := func(id string) int {
		t.Helper()
		var body struct {
			Data []any `json:"data"`
		}
		r, gerr := doWithAuth(t, "GET", fmt.Sprintf("%s/api/v1/sboms/%s/vulns", srv.URL, id), "", memberKey)
		is.NoErr(gerr)
		defer r.Body.Close()
		is.NoErr(json.NewDecoder(r.Body).Decode(&body))
		return len(body.Data)
	}
	is.Equal(vulnCount(a), 1)
	is.Equal(vulnCount(b), 1)
	is.Equal(vulnCount(c), 0) // stdlib@1.18.2 is in range, but Server.Serve is not linked
}
