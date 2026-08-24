import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The card stack is entirely CSS: DataTable emits `data-label` and one of two
 * wrapper classes, and the stylesheet does the rest. That split is exactly the
 * shape of bug this repo keeps finding — `tab-btn`, `tab-active`, two font
 * tokens, a shadowed `.text-sm` — where the markup is right, the rule is
 * missing or misspelled, and nothing fails because a stylesheet that does
 * nothing is not an assertion error.
 *
 * DataTable.test.tsx asserts the markup side. This asserts the rule side, and
 * that the two use the same names.
 */
const css = readFileSync(join(__dirname, "DataTable.css"), "utf-8").replace(
    /\/\*[\s\S]*?\*\//g,
    "",
);

/** The body of the `@media (max-width: 768px)` block. */
function mobileBlock(): string {
    const start = css.indexOf("@media (max-width: 768px)");
    if (start === -1) throw new Error("no mobile media query in DataTable.css");
    const open = css.indexOf("{", start);
    let depth = 0;
    for (let i = open; i < css.length; i++) {
        if (css[i] === "{") depth++;
        else if (css[i] === "}" && --depth === 0) return css.slice(open + 1, i);
    }
    throw new Error("unterminated mobile media query");
}

describe("mobile table styles", () => {
    const block = mobileBlock();

    it("hides the header row the cards replace", () => {
        expect(/\.table-mobile-cards thead\s*\{[^}]*display:\s*none/.test(block)).toBe(true);
    });

    it("reads the label DataTable writes", () => {
        // `data-label` is the whole contract between the component and the CSS.
        expect(block).toContain("content: attr(data-label)");
        expect(block).toContain("td[data-label]::before");
    });

    it("gives the opted-out table something to scroll", () => {
        // `table { width: 100% }` in index.css means a table can never exceed
        // its wrapper on its own, so `overflow-x: auto` has nothing to do until
        // a min-width asks for it. Without this line "scroll" mode is just a
        // squeezed table with a different class name.
        expect(/\.table-mobile-scroll table\s*\{[^}]*min-width:/.test(block)).toBe(true);
    });

    // The value gutter breaks anywhere so a purl or a digest can wrap;
    // `overflow-wrap` is inherited, so without an explicit reset the label
    // pseudo inherited that too and "VULNERABILITIES" rendered as
    // "VULNERABILITIE / S" in a 6.5rem gutter (ocidex-ag4q.61). Both halves
    // matter: a wider gutter alone still permits the break on the next long
    // label, and the reset alone leaves the longest one overflowing.
    it("keeps the label out of the value's break-anywhere rule", () => {
        const label = /td\[data-label\]::before\s*\{([^}]*)\}/.exec(block);
        if (label === null) throw new Error("no label pseudo rule");
        expect(label[1]).toMatch(/overflow-wrap:\s*normal/);
        const basis = /flex:\s*0\s+0\s+([\d.]+)rem/.exec(label[1]);
        if (basis === null) throw new Error("label gutter has no rem flex-basis");
        expect(Number(basis[1])).toBeGreaterThanOrEqual(7.5);
    });

    it("only styles classes DataTable actually emits", () => {
        const emitted = ["table-mobile-cards", "table-mobile-scroll"];
        const used = [...block.matchAll(/\.table-mobile-[a-z]+/g)].map((m) => m[0].slice(1));
        expect([...new Set(used)].sort()).toEqual(emitted);
    });
});
