import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/**
 * Loading, error and empty are one ladder, and every page that wrote it by hand
 * wrote a slightly different one (ocidex-ag4q.43). The divergences were never
 * in the obvious rung:
 *
 *   - `SBOMDetail` and `ComponentDetail` collapsed "no data" into the error
 *     branch, so a 200 with nothing in it told the reader "an unexpected error
 *     occurred".
 *   - `RunningWorkloads` had no error branch at all, so a failed request
 *     rendered "No running workload matched" — a claim about the cluster made
 *     from an answer that never arrived.
 *   - `DiffPairView` used three *sibling* `<Show>`s, so an error arriving over
 *     stale data painted the ErrorBox and the tree at once.
 *
 * `<QueryBoundary>` is the single ladder; `error` and `empty` are there so
 * better copy is a reason to pass a prop, not a reason to hand-roll it again.
 *
 * The second rule is about refetch. `db34570` made `DataTable` dim its rows
 * instead of blanking them, but that only works if the call site hands it
 * `isFetching`: TanStack's `isLoading` is first-load-only, so a table fed
 * `isLoading` silently never dims and never sets `aria-busy`.
 */

const SRC = __dirname;

/** Source with comments stripped, so prose explaining a rule cannot satisfy it. */
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

const files = [...sources(join(SRC, "pages")), ...sources(join(SRC, "components"))];

/**
 * The generic boundaries are allowed to name `isLoading` — implementing the
 * ladder is their whole job. Everything else has to go through one of them.
 */
const BOUNDARIES = ["components/ui/QueryBoundary.tsx", "components/Feedback.tsx", "pages/Lookup.tsx"];

function isBoundary(file: string): boolean {
    const rel = relative(SRC, file);
    return BOUNDARIES.some((b) => rel === b);
}

describe("query state adoption", () => {
    it("leaves no page hand-rolling the loading rung", () => {
        // `<Show when={!q.isLoading} fallback={…}>` is the shape every one of
        // the hand-rolled ladders opened with. Inline `{q.isLoading ? <Skeleton
        // inline/> : name}` placeholders are deliberately not covered: they
        // stand in for one string inside a breadcrumb, not for a page state.
        const ladder = /when=\{\s*!\s*(?!props\.)[A-Za-z_$][\w.$]*\.isLoading\s*\}/;
        const offenders = files
            .filter((f) => !isBoundary(f))
            .filter((f) => ladder.test(code(f)))
            .map((f) => relative(SRC, f));
        expect(offenders).toEqual([]);
    });

    it("leaves no page hand-rolling the error rung", () => {
        // The rung below it: `<Show when={!q.isError} fallback={<ErrorBox …>}`.
        // `props.isError` is excluded: DataTable and RelationshipsTab are fed
        // their state by a parent that already owns the query, so there is no
        // query for them to route through.
        const rung = /when=\{\s*!\s*(?!props\.)[A-Za-z_$][\w.$]*\.isError\s*\}/;
        const offenders = files
            .filter((f) => !isBoundary(f))
            .filter((f) => rung.test(code(f)))
            .map((f) => relative(SRC, f));
        expect(offenders).toEqual([]);
    });

    it("feeds every table's loading prop isFetching, never isLoading", () => {
        const offenders = files
            .filter((f) => /loading=\{[^}]*\.isLoading[^}]*\}/.test(code(f)))
            .map((f) => relative(SRC, f));
        expect(offenders).toEqual([]);
    });

    it("keeps QueryBoundary's error and empty branches distinct", () => {
        const src = code(join(SRC, "components/ui/QueryBoundary.tsx"));
        // The error fallback must be reachable without data, and the empty
        // fallback must be reachable without an error — the two bugs this
        // component exists to prevent.
        expect(src).toMatch(/props\.error \?\? <ErrorBox/);
        expect(src).toMatch(/fallback=\{props\.empty\}/);
    });

    it("uses QueryBoundary on every detail page", () => {
        const details = [
            "pages/ArtifactDetail/index.tsx",
            "pages/ComponentDetail/index.tsx",
            "pages/ComponentOverview/index.tsx",
            "pages/SBOMDetail/index.tsx",
            "pages/VulnerabilityDetail.tsx",
            "pages/ClusterDetail/index.tsx",
            "pages/ArtifactVersionHistory.tsx",
        ];
        const missing = details.filter(
            (rel) => !code(join(SRC, rel)).includes("<QueryBoundary"),
        );
        expect(missing).toEqual([]);
    });
});
