// Command vuln-parity compares grype's matches for stored SBOMs against the
// OSV-derived package_vulnerability mappings (ADR-049). It is a migration aid:
// run it before and after switching the vuln-worker to grype to see exactly
// which findings appear, disappear, or survive.
//
// Usage:
//
//	go run ./cmd/vuln-parity -db-dir ~/.cache/grype/db sbom.cdx.json ...   # files: print findings
//	DATABASE_URL=... go run ./cmd/vuln-parity -db-dir ... -sboms 20        # stored SBOMs: diff
//
// Findings are compared by canonical ID (the CVE when one is known), the same
// grouping the read-side queries use.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/pfenerty/ocidex/internal/vuln/grypematch"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	dbDir := flag.String("db-dir", "", "grype database root directory (required)")
	update := flag.Bool("update", false, "download or update the grype database first")
	n := flag.Int("sboms", 0, "compare the N most recently created stored SBOMs (needs DATABASE_URL)")
	verbose := flag.Bool("v", false, "list each differing finding")
	flag.Parse()
	if *dbDir == "" {
		return fmt.Errorf("-db-dir is required")
	}

	provider, status, err := grypematch.LoadDB(grypematch.DBConfig{RootDir: *dbDir}, *update)
	if err != nil {
		return fmt.Errorf("loading grype db: %w", err)
	}
	m := grypematch.NewMatcher(provider)
	defer func() { _ = m.Close() }()
	fmt.Printf("grype db built %s (schema %s)\n", status.Built.Format("2006-01-02T15:04Z"), status.SchemaVersion)

	ctx := context.Background()
	for _, path := range flag.Args() {
		doc, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied path
		if err != nil {
			return err
		}
		findings, err := m.Match(ctx, doc)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Printf("\n%s: %d findings\n", path, len(findings))
		for _, f := range findings {
			fmt.Printf("  %-28s %-10s %-10s %s fixed=%s\n", canonical(f), severity(f), f.FixState, f.Purl, f.FixedVersion)
		}
	}
	if *n > 0 {
		return compareStored(ctx, m, *n, *verbose)
	}
	return nil
}

func compareStored(ctx context.Context, m *grypematch.Matcher, n int, verbose bool) error {
	conn, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()

	rows, err := conn.Query(ctx, `SELECT id::text, raw_bom::text FROM sbom ORDER BY created_at DESC LIMIT $1`, n)
	if err != nil {
		return err
	}
	type sbomDoc struct{ id, raw string }
	var docs []sbomDoc
	for rows.Next() {
		var d sbomDoc
		if err := rows.Scan(&d.id, &d.raw); err != nil {
			return err
		}
		docs = append(docs, d)
	}
	rows.Close()

	var tBoth, tGrype, tOSV int
	for _, d := range docs {
		findings, err := m.Match(ctx, []byte(d.raw))
		if err != nil {
			fmt.Printf("%s: match failed: %v\n", d.id, err)
			continue
		}
		g := map[string]string{}
		for _, f := range findings {
			g[canonical(f)] = f.Purl
		}
		o, err := storedFindings(ctx, conn, d.id)
		if err != nil {
			return err
		}
		both, gOnly, oOnly := diff(g, o)
		tBoth, tGrype, tOSV = tBoth+len(both), tGrype+len(gOnly), tOSV+len(oOnly)
		fmt.Printf("%s: both=%d grype-only=%d osv-only=%d\n", d.id, len(both), len(gOnly), len(oOnly))
		if verbose {
			for _, id := range gOnly {
				fmt.Printf("  + %-28s %s\n", id, g[id])
			}
			for _, id := range oOnly {
				fmt.Printf("  - %-28s %s\n", id, o[id])
			}
		}
	}
	fmt.Printf("\ntotal: both=%d grype-only=%d osv-only=%d across %d sboms\n", tBoth, tGrype, tOSV, len(docs))
	return nil
}

// storedFindings returns canonical ID → purl for the SBOM's current OSV-derived
// mappings, over the same purl ∪ source_purl scope ListSBOMVulns uses.
func storedFindings(ctx context.Context, conn *pgx.Conn, sbomID string) (map[string]string, error) {
	rows, err := conn.Query(ctx, `
		SELECT DISTINCT COALESCE(NULLIF(v.canonical_id, ''), v.id), c.purl
		FROM component c
		JOIN package_vulnerability pv ON pv.purl = c.purl OR pv.purl = c.source_purl
		JOIN vulnerability v ON v.id = pv.vulnerability_id
		WHERE c.sbom_id = $1::uuid`, sbomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, purl string
		if err := rows.Scan(&id, &purl); err != nil {
			return nil, err
		}
		out[id] = purl
	}
	return out, rows.Err()
}

func diff(g, o map[string]string) (both, gOnly, oOnly []string) {
	for id := range g {
		if _, ok := o[id]; ok {
			both = append(both, id)
		} else {
			gOnly = append(gOnly, id)
		}
	}
	for id := range o {
		if _, ok := g[id]; !ok {
			oOnly = append(oOnly, id)
		}
	}
	sort.Strings(gOnly)
	sort.Strings(oOnly)
	return both, gOnly, oOnly
}

func canonical(f grypematch.Finding) string {
	if strings.HasPrefix(f.VulnerabilityID, "CVE-") {
		return f.VulnerabilityID
	}
	for _, r := range f.Related {
		if strings.HasPrefix(r, "CVE-") {
			return r
		}
	}
	return f.VulnerabilityID
}

func severity(f grypematch.Finding) string {
	if f.Metadata == nil {
		return "Unknown"
	}
	return f.Metadata.Severity
}
