import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/**
 * `<Button>` is the one call site for the `.btn` family (ocidex-ag4q.12). This
 * asserts the directories that have been migrated stay migrated.
 *
 * The failure it guards is not hypothetical: `btn-secondary` shipped as a
 * hand-written class string that no rule in index.css ever defined, so the call
 * site silently got the default look — the same dead-class-name bug as
 * `tab-btn` and `tab-active`. A typo inside a string literal is invisible to
 * tsc and to ESLint; it is only visible to a rule like this one.
 *
 * MIGRATED grows as the Phase 2 sweep lands: ocidex-ag4q.19 covers the admin
 * tree, .20 the flat list pages, .21 the detail pages. Add each directory here
 * as its story closes, so a later edit cannot regress an earlier one.
 */
const MIGRATED = [
    "pages/admin",
    "pages/Admin.tsx",
    "pages/Clusters.tsx",
    "pages/Components.tsx",
    "pages/Diff.tsx",
    "pages/Licenses.tsx",
    "pages/Vulnerabilities.tsx",
];

const SRC = __dirname;

function sources(dir: string, acc: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) sources(full, acc);
        else if (full.endsWith(".tsx") && !full.endsWith(".test.tsx")) acc.push(full);
    }
    return acc;
}

function migratedFiles(): string[] {
    return MIGRATED.flatMap((m) => {
        const full = join(SRC, m);
        return statSync(full).isDirectory() ? sources(full) : [full];
    });
}

/**
 * A `class="… btn …"` string, i.e. the shape `<Button>` replaces.
 *
 * The `btn-?` alternation matters: three call sites wrote `class="btn-primary"`
 * with no `btn`, and `.btn-primary` sets only background/border/color — so they
 * rendered red with none of the padding, radius or font sizing that makes a
 * button a button. A pattern anchored on the word `btn` alone would have walked
 * straight past all three.
 */
const RAW_BTN = /class="[^"]*\bbtn(-[a-z]+)?\b[^"]*"/;

describe("migrated directories use the Button primitive", () => {
    it("carries no raw btn class strings", () => {
        const offenders = migratedFiles()
            .filter((f) => RAW_BTN.test(readFileSync(f, "utf-8")))
            .map((f) => relative(SRC, f));
        expect(offenders).toEqual([]);
    });

    it("never writes btn-secondary, which no rule defines", () => {
        // The bare `.btn` *is* the secondary button. `variant="secondary"`
        // deliberately emits no class; a literal `btn-secondary` anywhere means
        // someone assumed a rule that does not exist.
        const offenders = sources(SRC)
            .filter((f) => readFileSync(f, "utf-8").includes("btn-secondary"))
            .map((f) => relative(SRC, f));
        expect(offenders).toEqual(["components/ui/Button.tsx"]);
    });
});
