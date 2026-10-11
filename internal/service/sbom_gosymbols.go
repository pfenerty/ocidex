package service

import (
	"bytes"
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5"

	"github.com/pfenerty/ocidex/internal/gosymbols"
)

// detachGoSymbols lifts the ocidex Go symbol properties (ADR-050) off bom's
// components, keyed by component, and returns the document to persist without
// them, so symbols are stored once — relationally — rather than also inside
// raw_bom. rawJSON is returned unchanged when the BOM carries no symbols.
func detachGoSymbols(bom *cdx.BOM, rawJSON []byte) (map[*cdx.Component]gosymbols.Table, []byte, error) {
	if bom == nil || bom.Components == nil {
		return nil, rawJSON, nil
	}
	syms := map[*cdx.Component]gosymbols.Table{}
	var walk func(comps []cdx.Component)
	walk = func(comps []cdx.Component) {
		for i := range comps {
			c := &comps[i]
			if c.Properties != nil {
				if t, _ := gosymbols.FromProperties(*c.Properties); t != nil {
					syms[c] = gosymbols.Normalized(t)
				}
			}
			if c.Components != nil {
				walk(*c.Components)
			}
		}
	}
	walk(*bom.Components)
	if len(syms) == 0 {
		return nil, rawJSON, nil
	}
	gosymbols.Strip(bom)
	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).Encode(bom); err != nil {
		return nil, nil, fmt.Errorf("re-encoding sbom without go symbols: %w", err)
	}
	return syms, buf.Bytes(), nil
}

// goSymbolSetDigest is the content address of a set: sha256 over its sorted
// symbol ids, comma-joined. Computed in SQL so the set, its digest and the
// component link are resolved in one pass.
const goSymbolSetDigest = `sha256(convert_to(array_to_string(ids, ','), 'UTF8'))`

// persistGoSymbols stores the symbol table of each component that has one: new
// import paths and symbols join the dictionary, each component's symbol list is
// resolved to a content-addressed set (shared with every other component that
// links exactly the same symbols), and the component is linked to it. All of it
// is set-based inside the ingest transaction.
func persistGoSymbols(ctx context.Context, tx copyFromer, flat []flatComponent, syms map[*cdx.Component]gosymbols.Table) error {
	if len(syms) == 0 {
		return nil
	}
	var rows [][]any
	for _, fc := range flat {
		for path, names := range syms[fc.comp] {
			if len(names) == 0 {
				rows = append(rows, []any{fc.id, path, ""}) // present, no symbols
				continue
			}
			for _, n := range names {
				rows = append(rows, []any{fc.id, path, n})
			}
		}
	}
	if len(rows) == 0 {
		return nil
	}

	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE tmp_go_symbols (
		component_id UUID NOT NULL, import_path TEXT NOT NULL, name TEXT NOT NULL
	) ON COMMIT DROP`); err != nil {
		return fmt.Errorf("creating go symbol staging table: %w", err)
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"tmp_go_symbols"},
		[]string{"component_id", "import_path", "name"}, pgx.CopyFromRows(rows)); err != nil {
		return fmt.Errorf("staging go symbols: %w", err)
	}
	for _, step := range []struct{ what, sql string }{
		{"go packages", `INSERT INTO go_package (import_path)
			SELECT DISTINCT import_path FROM tmp_go_symbols
			ON CONFLICT (import_path) DO NOTHING`},
		{"go symbols", `INSERT INTO go_symbol (package_id, name)
			SELECT DISTINCT p.id, t.name
			FROM tmp_go_symbols t JOIN go_package p ON p.import_path = t.import_path
			ON CONFLICT (package_id, name) DO NOTHING`},
		{"go symbol set staging", `CREATE TEMP TABLE tmp_go_sets ON COMMIT DROP AS
			SELECT t.component_id, array_agg(DISTINCT s.id ORDER BY s.id) AS ids
			FROM tmp_go_symbols t
			JOIN go_package p ON p.import_path = t.import_path
			JOIN go_symbol s ON s.package_id = p.id AND s.name = t.name
			GROUP BY t.component_id`},
		{"go symbol sets", `INSERT INTO go_symbol_set (digest, symbol_ids, symbol_count)
			SELECT DISTINCT ON (digest) digest, ids, cardinality(ids)
			FROM (SELECT ` + goSymbolSetDigest + ` AS digest, ids FROM tmp_go_sets) x
			ON CONFLICT (digest) DO NOTHING`},
		{"component go symbol links", `UPDATE component c SET go_symbol_set_id = gs.id
			FROM tmp_go_sets t
			JOIN go_symbol_set gs ON gs.digest = ` + goSymbolSetDigest + `
			WHERE c.id = t.component_id`},
	} {
		if _, err := tx.Exec(ctx, step.sql); err != nil {
			return fmt.Errorf("persisting %s: %w", step.what, err)
		}
	}
	return nil
}
