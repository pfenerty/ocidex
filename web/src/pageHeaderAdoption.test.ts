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
 * MIGRATED grows as the sweep lands: ocidex-ag4q.22 covers the list pages,
 * .23 the detail pages.
 */
const MIGRATED = [
    "pages/Admin.tsx",
    "pages/Artifacts.tsx",
    "pages/Clusters.tsx",
    "pages/Components.tsx",
    "pages/Diff.tsx",
    "pages/LicenseComponents.tsx",
    "pages/Licenses.tsx",
    "pages/Vulnerabilities.tsx",
];

/**
 * Skeleton deliberately emits the real structure rather than the primitive: it
 * is a placeholder standing in for a header that has not loaded, so it must
 * match the markup byte for byte without importing the thing it replaces.
 */
const ALLOWED = ["components/ui/PageHeader.tsx", "components/Skeleton.tsx"];

const SRC = __dirname;

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
        const offenders = MIGRATED.filter((f) => code(join(SRC, f)).includes('class="page-header'));
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
        const src = code(join(SRC, "components/ui/PageHeader.tsx"));
        const row = /<div class="page-header-row">([\s\S]*?)<\/div>\s*<\/div>/.exec(src)?.[1] ?? "";
        expect(row).toMatch(/<div>\s*<h2>/);
    });

    it("is emitted from nowhere else", () => {
        const offenders = sources(SRC)
            .filter((f) => code(f).includes('class="page-header'))
            .map((f) => relative(SRC, f))
            .filter((f) => !ALLOWED.includes(f));
        // Part 2 (.23) empties this. Until then it is the exact remaining list,
        // so a *new* hand-written header still fails.
        expect(offenders).toEqual([
            "pages/ArtifactDetail/ArtifactHeader.tsx",
            "pages/ArtifactVersionHistory.tsx",
            "pages/ClusterDetail/index.tsx",
            "pages/ComponentDetail/index.tsx",
            "pages/ComponentOverview/index.tsx",
            "pages/Dashboard/index.tsx",
            "pages/Lookup.tsx",
            "pages/SBOMDetail/index.tsx",
            "pages/VulnerabilityDetail.tsx",
        ]);
    });
});
