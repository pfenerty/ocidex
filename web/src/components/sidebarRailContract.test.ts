// @vitest-environment node
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The mobile sidebar is one element in two states: a 56px icon rail, and the
 * same element expanded into a drawer. Every label the rail hides, the drawer
 * has to show again — and the bug this replaced (ocidex-ag4q.49) was exactly a
 * label missing from one of those two lists: the footer's "Sign in with GitHub"
 * was never hidden, so it wrapped over three lines inside the 56px column.
 *
 * happy-dom has no layout engine and no cascade to query, so this reads the
 * stylesheet as text. A visual check catches the miss once; this keeps it
 * caught when someone adds the next labelled control to the sidebar.
 */

const CSS = join(__dirname, "Layout.css");

/** The body of the `@media (max-width: 768px)` block, comments stripped. */
function mobileBlock(): string {
    const css = readFileSync(CSS, "utf-8").replace(/\/\*[\s\S]*?\*\//g, "");
    const start = css.indexOf("@media (max-width: 768px)");
    expect(start).toBeGreaterThanOrEqual(0);
    const open = css.indexOf("{", start);
    let depth = 0;
    for (let i = open; i < css.length; i++) {
        if (css[i] === "{") depth++;
        else if (css[i] === "}") {
            depth--;
            if (depth === 0) return css.slice(open + 1, i);
        }
    }
    throw new Error("unterminated @media block in Layout.css");
}

/** Every `selector { … }` rule in a block, as [selectors, declarations]. */
function rules(block: string): [string[], string][] {
    const out: [string[], string][] = [];
    const re = /([^{}]+)\{([^{}]*)\}/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(block)) !== null) {
        out.push([m[1].split(",").map((s) => s.trim()).filter((s) => s !== ""), m[2]]);
    }
    return out;
}

/**
 * Drop the state token, so `.sidebar nav a span` and `.sidebar-open nav a span`
 * name the same thing and can be compared as sets.
 */
function withoutState(selector: string): string {
    return selector.replace(/^\.sidebar(-open)?\s+/, "").trim();
}

function displayValue(decls: string): string | undefined {
    const m = /(?:^|;)\s*display\s*:\s*([^;]+)/.exec(decls);
    return m === null ? undefined : m[1].trim();
}

/** What the rail hides, and what the drawer puts back — state token stripped. */
function displayStates(): { hidden: Set<string>; shown: Set<string> } {
    const hidden = new Set<string>();
    const shown = new Set<string>();

    for (const [selectors, decls] of rules(mobileBlock())) {
        const display = displayValue(decls);
        if (display === undefined) continue;
        for (const selector of selectors) {
            // The backdrop and the toggle are chrome, not content: they exist
            // in only one state by design.
            if (/\.sidebar-backdrop|\.sidebar-drawer-toggle/.test(selector)) continue;
            const isDrawer = selector.startsWith(".sidebar-open");
            if (display === "none" && !isDrawer) hidden.add(withoutState(selector));
            else if (display !== "none" && isDrawer) shown.add(withoutState(selector));
        }
    }
    return { hidden, shown };
}

describe("mobile sidebar rail/drawer contract", () => {
    it("shows in the drawer everything it hides in the rail", () => {
        const { hidden, shown } = displayStates();
        expect(hidden.size).toBeGreaterThan(0);
        expect([...shown].sort()).toEqual([...hidden].sort());
    });

    it("hides the footer labels, which is what wrapped over three lines", () => {
        const { hidden } = displayStates();
        expect(hidden).toContain(".sidebar-sign-in span");
        expect(hidden).toContain(".sidebar-user-info span");
    });

    it("lifts the open drawer out of flow so it does not shove the article", () => {
        const positioned = rules(mobileBlock()).some(
            ([selectors, decls]) =>
                selectors.includes(".sidebar-open") && /position\s*:\s*fixed/.test(decls),
        );
        expect(positioned).toBe(true);
    });
});
