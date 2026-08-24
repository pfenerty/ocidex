import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/**
 * `<PageHeader>` is the one writer of the `.page-header` / `.page-header-row`
 * structure (ocidex-ag4q.13).
 *
 * The nesting is what needs guarding, not the class name. `.page-header-row` is
 * `justify-content: space-between`, so a hand-written header that forgets to
 * wrap its `h2` and `p` in a single child spreads the title and subtitle to
 * opposite ends of the row — a layout bug with no failing assertion anywhere,
 * because every class involved is real and spelled correctly.
 *
 * The sweep is complete — ocidex-ag4q.22 took the list pages, .23 the detail
 * pages — so the scope below is the whole of src and ALLOWED is exhaustive.
 * MIGRATED is kept as a named list so the second test can assert each of those
 * files actually reaches for the primitive, rather than merely not naming the
 * class.
 */
const MIGRATED = [
    "pages/Admin.tsx",
    "pages/ArtifactDetail/ArtifactHeader.tsx",
    "pages/Artifacts.tsx",
    "pages/ArtifactVersionHistory.tsx",
    "pages/ClusterDetail/index.tsx",
    "pages/Clusters.tsx",
    "pages/ComponentDetail/index.tsx",
    "pages/ComponentOverview/index.tsx",
    "pages/Components.tsx",
    "pages/Dashboard/index.tsx",
    "pages/Diff.tsx",
    "pages/LicenseComponents.tsx",
    "pages/Licenses.tsx",
    "pages/Lookup.tsx",
    "pages/SBOMDetail/index.tsx",
    "pages/VulnerabilityDetail.tsx",
    "pages/Vulnerabilities.tsx",
];

/**
 * Skeleton deliberately emits the real structure rather than the primitive: it
 * is a placeholder standing in for a header that has not loaded, so it must
 * match the markup byte for byte without importing the thing it replaces.
 */
const ALLOWED = ["components/ui/PageHeader.tsx", "components/Skeleton.tsx"];

const SRC = __dirname;

/**
 * The two structural classes, and only those. A prefix match would also catch
 * `page-header-badges`, a different class entirely — and one that no stylesheet
 * ever defined, which is why .23 deleted it rather than exempting it here.
 */
const STRUCTURE = /class="(page-header|page-header-row)"/;

/** Source with comments stripped, so prose naming a class stops matching it. */
function code(file: string): string {
    return readFileSync(file, "utf-8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/[^\n]*/g, "");
}

function sources(dir: string, acc: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) sources(full, acc);
        else if (full.endsWith(".tsx") && !full.endsWith(".test.tsx")) acc.push(full);
    }
    return acc;
}

describe("migrated pages use the PageHeader primitive", () => {
    it("hand-writes no .page-header markup", () => {
        const offenders = MIGRATED.filter((f) => STRUCTURE.test(code(join(SRC, f))));
        expect(offenders).toEqual([]);
    });

    it("imports it from the barrel", () => {
        const missing = MIGRATED.filter((f) => !code(join(SRC, f)).includes("PageHeader"));
        expect(missing).toEqual([]);
    });
});

describe("the .page-header-row wrapper", () => {
    it("keeps the title and subtitle in one child of the row", () => {
        // Two children of a space-between row are pushed apart. The primitive's
        // whole job is that this stays one child; assert it, because a refactor
        // that flattens the div looks tidier and renders wrong.
        // Anchored at the row's opening tag rather than delimited by its close:
        // `footer` renders after the row inside the same `.page-header`, so any
        // regex that tries to find the row's own `</div>` by counting tags is
        // guessing.
        const src = code(join(SRC, "components/ui/PageHeader.tsx"));
        expect(src).toMatch(/<div class="page-header-row">\s*<div>\s*<h2>/);
    });

    it("is emitted from nowhere else", () => {
        const offenders = sources(SRC)
            .filter((f) => STRUCTURE.test(code(f)))
            .map((f) => relative(SRC, f))
            .filter((f) => !ALLOWED.includes(f));
        expect(offenders).toEqual([]);
    });
});
