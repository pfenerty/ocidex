import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/**
 * `<Button>` is the one call site for the `.btn` family (ocidex-ag4q.12). This
 * asserts that it stays the only one.
 *
 * The failure it guards is not hypothetical: `btn-secondary` shipped as a
 * hand-written class string that no rule in index.css ever defined, so the call
 * site silently got the default look — the same dead-class-name bug as
 * `tab-btn` and `tab-active`. A typo inside a string literal is invisible to
 * tsc and to ESLint; it is only visible to a rule like this one.
 *
 * The sweep landed over three stories — ocidex-ag4q.19 the admin tree, .20 the
 * flat list pages, .21 the detail pages and shared components — so the scope is
 * now the whole of src, and ALLOWED is the exhaustive list of files permitted to
 * name a `.btn` class at all.
 */
const ALLOWED = ["components/ui/Button.tsx", "components/ui/ButtonGroup.tsx"];

const SRC = __dirname;

/**
 * Source with comments removed. Without this the prose *explaining* a rule
 * matches it — three doc comments mention `.btn-group` by name, and a contract
 * test that trips on its own documentation trains people to delete the
 * documentation.
 */
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

/**
 * A `class="… btn …"` string, i.e. the shape `<Button>` / `<ButtonGroup>` replaces.
 *
 * The `btn-?` alternation matters: three call sites wrote `class="btn-primary"`
 * with no `btn`, and `.btn-primary` sets only background/border/color — so they
 * rendered red with none of the padding, radius or font sizing that makes a
 * button a button. A pattern anchored on the word `btn` alone would have walked
 * straight past all three.
 *
 * The lookbehind is what keeps `sidebar-logout-btn` out. That class is its own
 * rule in Layout.css and shares nothing with the `.btn` family beyond the three
 * letters, so matching it would be a false positive — but a bare `\b` matches
 * after a hyphen, because a hyphen is not a word character.
 */
const RAW_BTN = /class="[^"]*(?<![-\w])btn(-[a-z]+)?\b[^"]*"/;

describe("the whole tree uses the Button primitive", () => {
    it("names a btn class nowhere but the primitives themselves", () => {
        const offenders = sources(SRC)
            .filter((f) => RAW_BTN.test(code(f)))
            .map((f) => relative(SRC, f))
            .filter((f) => !ALLOWED.includes(f));
        expect(offenders).toEqual([]);
    });

    it("keeps .btn-group paired with the rule that styles its children", () => {
        // `index.css` styles `.btn-group .btn.active` — a pressed toggle only
        // reads as pressed inside the group. Emitting the container from one
        // primitive is what stops `active` from being set somewhere the rule
        // cannot reach.
        const offenders = sources(SRC)
            .filter((f) => code(f).includes("btn-group"))
            .map((f) => relative(SRC, f));
        expect(offenders).toEqual([ALLOWED[1]]);
    });

    it("never writes btn-secondary, which no rule defines", () => {
        // The bare `.btn` *is* the secondary button. `variant="secondary"`
        // deliberately emits no class; a literal `btn-secondary` anywhere means
        // someone assumed a rule that does not exist. Button.tsx used to be the
        // one permitted mention, in the doc comment saying exactly that — but
        // `code()` strips comments now, so the expectation is a clean zero.
        const offenders = sources(SRC)
            .filter((f) => code(f).includes("btn-secondary"))
            .map((f) => relative(SRC, f));
        expect(offenders).toEqual([]);
    });
});
