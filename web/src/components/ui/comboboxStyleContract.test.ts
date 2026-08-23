import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { resolve, join } from "path";

/**
 * The combobox's list is absolutely positioned over the page. If any one of
 * those four properties goes missing the control does not *look* broken in
 * happy-dom — there is no layout engine there, so every one of Combobox's
 * behavioural tests still passes while the real list renders inline, shoving
 * the form down the page, or slides under the card beside it.
 *
 * That is the "the CSS silently did nothing" class this repo pairs a contract
 * test with (ocidex-ag4q.41).
 */
const HERE = resolve(__dirname);

function rule(css: string, selector: string): string {
    const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const m = new RegExp(`${escaped}[^{}]*\\{([^}]*)\\}`).exec(css);
    if (m === null) throw new Error(`no rule for ${selector} in Combobox.css`);
    return m[1];
}

describe("Combobox style contract", () => {
    const css = readFileSync(join(HERE, "Combobox.css"), "utf8");
    const tsx = readFileSync(join(HERE, "Combobox.tsx"), "utf8");

    it("imports its own stylesheet", () => {
        expect(tsx).toContain("Combobox.css");
    });

    it("floats the list over the page instead of in the flow", () => {
        expect(rule(css, ".combobox ")).toContain("position: relative");

        const list = rule(css, ".combobox-list");
        expect(list).toContain("position: absolute");
        // Without a z-index the list renders beneath the next card.
        expect(list).toMatch(/z-index:\s*\d+/);
        // Without a max-height a 200-SBOM list runs off the bottom of the page,
        // which is the scroll-instead-of-type problem this control replaced.
        expect(list).toContain("max-height");
        expect(list).toContain("overflow-y: auto");
    });

    it("gives every class the component emits a rule", () => {
        for (const cls of tsx.matchAll(/"(combobox-[a-z-]+)"/g)) {
            expect(css, `missing rule for .${cls[1]}`).toContain(`.${cls[1]}`);
        }
    });

    it("highlights with the interactive blue, not the brand red", () => {
        const active = rule(css, ".combobox-option.is-active");
        expect(active).toContain("var(--color-info-bg)");
        expect(active).not.toContain("--color-primary");
    });
});
