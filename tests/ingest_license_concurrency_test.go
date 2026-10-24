package tests

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// licenseOrderSBOM is an SBOM whose components mention licenses in the given
// order, so two ingests can meet the same licenses in opposite orders.
func licenseOrderSBOM(t *testing.T, n int, licenses []string) (*cdx.BOM, []byte) {
	t.Helper()
	comps := make([]cdx.Component, len(licenses))
	for i, id := range licenses {
		comps[i] = cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: fmt.Sprintf("lib-%d-%d", n, i), Version: "1.0.0",
			Licenses: &cdx.Licenses{{License: &cdx.License{ID: id}}},
		}
	}
	bom := cdx.BOM{
		BOMFormat: cdx.BOMFormat, SpecVersion: cdx.SpecVersion1_6, Version: 1,
		SerialNumber: fmt.Sprintf("urn:uuid:5e000000-0000-0000-0000-%012d", n),
		Metadata: &cdx.Metadata{Component: &cdx.Component{
			// The validator is nil, so a digest in the name is stored, not checked.
			Type: cdx.ComponentTypeContainer, Version: "1.0.0",
			Name: fmt.Sprintf("registry.test/license-order-%d@sha256:%064d", n, n),
		}},
		Components: &comps,
	}
	raw, err := json.Marshal(&bom)
	if err != nil {
		t.Fatalf("encoding sbom %d: %v", n, err)
	}
	return &bom, raw
}

// TestConcurrentIngestLicenseOrder covers ocidex-5prp: concurrent ingests whose
// components list the same licenses in opposite orders must not deadlock on
// the license upsert, and must resolve each license to one row.
func TestConcurrentIngestLicenseOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	is := is.New(t)
	pool, cleanDB := setupTestDB(t)
	defer cleanDB()

	owner := seedUser(t, pool, 5150, "license-order", "member")
	ns := seedNamespace(t, pool, "license-order", owner, "public")
	var source pgtype.UUID
	is.NoErr(source.Scan(seedSource(t, pool, ns, "upload", "ci")))
	svc := service.NewSBOMService(pool, nil, nil)

	forward := []string{"MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "MPL-2.0", "GPL-2.0-only", "LGPL-2.1-only", "0BSD"}
	reverse := make([]string, len(forward))
	for i, l := range forward {
		reverse[len(forward)-1-i] = l
	}

	const rounds, perRound = 10, 8
	for r := range rounds {
		var wg sync.WaitGroup
		errs := make(chan error, perRound)
		for i := range perRound {
			order := forward
			if i%2 == 1 {
				order = reverse
			}
			bom, raw := licenseOrderSBOM(t, r*perRound+i, order)
			wg.Go(func() {
				if _, err := svc.Ingest(t.Context(), bom, raw, service.IngestParams{SourceID: source, Architecture: "amd64", BuildDate: "2026-01-01T00:00:00Z"}); err != nil {
					errs <- err
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("round %d: concurrent ingest failed: %v", r, err)
		}
	}

	var licenses, joins int
	is.NoErr(pool.QueryRow(t.Context(), `SELECT count(*) FROM license`).Scan(&licenses))
	is.NoErr(pool.QueryRow(t.Context(), `SELECT count(*) FROM component_license`).Scan(&joins))
	is.Equal(licenses, len(forward))
	is.Equal(joins, rounds*perRound*len(forward))
}
