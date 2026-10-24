package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

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

// TestIngestDoesNotWaitOnArtifactOrLicenseLocks covers ocidex-q1ni: while
// another transaction has upserted the same artifact and license and not yet
// committed, as a concurrent ingest of the same image does, an ingest of a new
// version must finish without waiting for it.
func TestIngestDoesNotWaitOnArtifactOrLicenseLocks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	is := is.New(t)
	pool, cleanDB := setupTestDB(t)
	defer cleanDB()

	owner := seedUser(t, pool, 5151, "artifact-lock", "member")
	ns := seedNamespace(t, pool, "artifact-lock", owner, "public")
	var source pgtype.UUID
	is.NoErr(source.Scan(seedSource(t, pool, ns, "upload", "ci")))
	svc := service.NewSBOMService(pool, nil, nil)
	params := service.IngestParams{SourceID: source, Architecture: "amd64", BuildDate: "2026-01-01T00:00:00Z"}

	// The same image name for every ingest: one artifact, as a multi-arch push.
	sbom := func(n int) (*cdx.BOM, []byte) {
		bom, _ := licenseOrderSBOM(t, n, []string{"MIT"})
		bom.Metadata.Component.Name = fmt.Sprintf("registry.test/one-image@sha256:%064d", n)
		raw, err := json.Marshal(bom)
		is.NoErr(err)
		return bom, raw
	}
	bom, raw := sbom(1)
	_, err := svc.Ingest(t.Context(), bom, raw, params)
	is.NoErr(err)

	// An ingest in flight: it has upserted the artifact and the license, and
	// holds their row locks until it commits.
	tx, err := pool.Begin(t.Context())
	is.NoErr(err)
	defer tx.Rollback(context.Background()) //nolint:errcheck // test cleanup
	_, err = tx.Exec(t.Context(), `
		INSERT INTO artifact (type, name) VALUES ('container', 'registry.test/one-image')
		ON CONFLICT (type, name, COALESCE(group_name, '')) DO UPDATE SET purl = artifact.purl`)
	is.NoErr(err)
	_, err = tx.Exec(t.Context(), `
		INSERT INTO license (spdx_id, name) VALUES ('MIT', 'MIT')
		ON CONFLICT (spdx_id) WHERE spdx_id IS NOT NULL DO UPDATE SET name = EXCLUDED.name`)
	is.NoErr(err)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	bom, raw = sbom(2)
	_, err = svc.Ingest(ctx, bom, raw, params)
	is.NoErr(err) // did not wait for the other transaction's locks
}
