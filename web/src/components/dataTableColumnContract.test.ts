import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * `Column.class` is the only width policy a table in this app has. Nothing
 * enforces that the classes call sites name actually resolve to a rule — a
 * misspelled or deleted one leaves the table looking exactly like it did before
 * anyone thought about widths, which is the state this file exists to prevent.
 *
 * The bug: `table { width: 100% }` with auto layout gives surplus width to the
 * column with the largest max-content contribution. The Gaps tab's image column
 * holds one unbreakable token, so it took roughly nine tenths of the table and
 * squeezed the remedy column the tab exists to show. Verified in the browser at
 * 1440/1024/500px (ocidex-383d.1).
 */
const css = readFileSync(join(__dirname, "DataTable.css"), "utf-8");

/** The body of the rule whose selector list contains `selector`. */
function rule(selector: string, within = css): string {
    const i = within.indexOf(selector);
    if (i === -1) throw new Error(`no rule for ${selector}`);
    const open = within.indexOf("{", i);
    const close = within.indexOf("}", open);
    return within.slice(open + 1, close);
}

describe("column width policy", () => {
    // Both halves matter. The cap alone leaves the ref overflowing its cell;
    // the wrap alone leaves min-content at the full string, so the cap has
    // nothing to cap down to and the column is as greedy as it ever was.
    it("caps an identifier column and lets its value wrap", () => {
        const body = rule("th.col-ref");
        expect(body).toMatch(/max-width:\s*[\d.]+rem/);
        expect(body).toMatch(/overflow-wrap:\s*anywhere/);
    });

    // `overflow-wrap: anywhere` sets min-content to one character, so the cap
    // inverts under pressure without a floor beneath it: measured at a 1024px
    // viewport, the Gaps image column collapsed to 144px and broke a ref across
    // twelve lines (ocidex-383d.2).
    it("floors the identifier column as well as capping it", () => {
        expect(rule("th.col-ref")).toMatch(/min-width:\s*[\d.]+rem/);
    });

    // `.truncate` is the wrong tool for a ref: it takes the tail, and the tail
    // of an image ref is the tag.
    it("does not truncate what it caps", () => {
        expect(rule("th.col-ref")).not.toMatch(/text-overflow|white-space:\s*nowrap/);
    });

    it("floors a column of controls", () => {
        expect(rule("th.col-action")).toMatch(/min-width:\s*[\d.]+rem/);
    });

    // Same reasoning as the `.truncate` undo beside it: the cap protects the
    // columns next to this one, and a card has none. Without the undo the ref
    // wraps inside 24rem on a 500px screen with the rest of the card empty.
    it("undoes the cap in the mobile card stack", () => {
        const start = css.indexOf("@media (max-width: 768px)");
        expect(start).toBeGreaterThan(-1);
        expect(rule(".table-mobile-cards tbody td.col-ref", css.slice(start))).toMatch(
            /max-width:\s*none/,
        );
    });
});
