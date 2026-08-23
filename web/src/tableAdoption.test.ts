import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/**
 * `<DataTable>` is the one call site for `<table>` markup (ocidex-ag4q.26/.27),
 * for the same reason `<Button>` and `<Card>` are: what diverges between
 * hand-rolled tables is never the obvious part.
 *
 * Two concrete failures this replaces, both found in the admin tree:
 *
 *   - `DriftFeedCard` wrote `<table class="table">`. No stylesheet has ever
 *     defined `.table` — the table was styled entirely by the bare `table` /
 *     `thead th` / `tbody td` element rules, so the class was decoration on a
 *     string, exactly like `tab-btn` and `page-header-badges` before it.
 *   - The same table had no `.table-wrapper`, which is where `overflow` and the
 *     sticky-header `max-height` live. It could not scroll sideways at any
 *     viewport; its five columns simply ran off the edge.
 *
 * Neither is visible to tsc, to ESLint, or to a rendering test that only asks
 * whether the rows are present.
 */

const SRC = __dirname;

/** Source with comments stripped, so prose explaining a rule cannot satisfy it. */
function code(file: string): string {
    return readFileSync(file, "utf-8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/[^\n]*/g, "");
}

function css(): string {
    return readFileSync(join(SRC, "index.css"), "utf-8").replace(/\/\*[\s\S]*?\*\//g, "");
}

function sources(dir: string, acc: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) sources(full, acc);
        else if (full.endsWith(".tsx") && !full.endsWith(".test.tsx")) acc.push(full);
    }
    return acc;
}

/**
 * The primitive itself, and the shimmer that has to mirror its markup in order
 * to occupy the same space.
 */
const ALLOWED = ["components/DataTable.tsx", "components/Skeleton.tsx"];

/**
 * Still hand-rolled, to be emptied by part 2 (.27). Pinned rather than
 * open-ended so a *new* hand-written table fails instead of joining a list.
 */
const REMAINING = [
    "components/ComponentMetadata.tsx",
    "components/DiffEntry.tsx",
    "components/DiffTreeView.tsx",
    "components/ProvenanceCard.tsx",
    "components/metadata/AnnotationsSection.tsx",
    "pages/Artifacts.tsx",
    "pages/ComponentOverview/ArtifactUsageTable.tsx",
    "pages/ComponentOverview/VersionListTable.tsx",
    "pages/SBOMDetail/DependencyTreeView.tsx",
    "pages/VulnerabilityDetail.tsx",
];

describe("table markup", () => {
    it("is confined to the primitive and the not-yet-migrated list", () => {
        const offenders = sources(SRC)
            .filter((f) => code(f).includes("<table"))
            .map((f) => relative(SRC, f))
            .filter((f) => !ALLOWED.includes(f));
        expect(offenders.sort()).toEqual(REMAINING);
    });

    it("never carries a `table` class, which no stylesheet defines", () => {
        const offenders = sources(SRC)
            .filter((f) => /class="[^"]*(?<![-\w])table(?![-\w])[^"]*"/.test(code(f)))
            .map((f) => relative(SRC, f));
        expect(offenders).toEqual([]);
        expect(css()).not.toMatch(/^\s*\.table\s*[,{]/m);
    });

    it("always sits inside the wrapper that gives it horizontal scroll", () => {
        // `.table-wrapper` is not cosmetic: it is the only element in the chain
        // carrying `overflow`, so a table outside one cannot scroll and cannot
        // keep its header sticky. ProvenanceCard is the last one without it.
        const offenders = sources(SRC)
            .filter((f) => code(f).includes("<table"))
            .filter((f) => !code(f).includes("table-wrapper"))
            .map((f) => relative(SRC, f));
        expect(offenders).toEqual(["components/ProvenanceCard.tsx"]);
    });
});

describe(".cell-button", () => {
    it("is a real rule that undoes the bare button element rule", () => {
        // A control inside a table cell has to read as text. The bare `button`
        // rule gives it a border, a background and padding first, so this rule
        // existing is the whole of the effect — the enricher matrix previously
        // spelled it out as an inline style on each of its fifteen buttons.
        const rule = /\.cell-button\s*\{([^}]*)\}/.exec(css());
        if (rule === null) throw new Error("no .cell-button rule in index.css");
        for (const decl of ["background: none", "border: none", "padding: 0"]) {
            expect(rule[1]).toContain(decl);
        }
    });

    it("marks the active filter in blue, not brand red", () => {
        const active = /\.cell-button\.active\s*\{([^}]*)\}/.exec(css());
        if (active === null) throw new Error("no .cell-button.active rule in index.css");
        expect(active[1]).toContain("--color-secondary");
        expect(active[1]).not.toContain("--color-primary");
    });
});
