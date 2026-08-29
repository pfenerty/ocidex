import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, join } from "node:path";

const SRC = resolve(__dirname, "../..");

/**
 * `<Button active>` emitted `.active` for as long as it existed, but the only
 * rule for it was `.btn-group .btn.active`. A toggle that is not one half of a
 * pair therefore flipped its class and its `aria-pressed` and computed the
 * *same* background either way — the Packages tab's "Vulnerable only" filter
 * looked unpressed while it was filtering (ocidex-unn8.12).
 *
 * That is the `tab-btn` failure one layer down: nothing errors, no test fails,
 * the stylesheet just does nothing. These tests hold the pressed look attached
 * to the primitive that claims it, and visibly different from the resting one.
 */
describe("Button pressed-state CSS contract", () => {
    const css = readFileSync(join(SRC, "index.css"), "utf8");
    const body = css.replace(/\/\*[\s\S]*?\*\//g, "");

    const rule = (selector: string): string => {
        const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const match = new RegExp(`^\\s*${escaped}\\s*\\{([^}]*)\\}`, "m").exec(body);
        if (match === null) throw new Error(`no rule for ${selector}`);
        return match[1];
    };

    it("styles .btn.active without requiring an enclosing .btn-group", () => {
        expect(rule(".btn.active")).toMatch(/background:\s*var\(--color-secondary\)/);
        expect(rule(".btn.active:hover")).toMatch(/background:\s*var\(--color-secondary-hover\)/);

        // The regression this file exists for: re-scoping the rule to the group
        // silently un-styles every standalone toggle.
        expect(body).not.toMatch(/\.btn-group\s+\.btn\.active/);
    });

    it("makes pressed visibly different from resting", () => {
        // Asserting the rule exists is not enough — `.btn.active { }` passes
        // that and renders identically to `.btn`, which is the bug verbatim.
        expect(rule(".btn")).toMatch(/background:\s*var\(--color-surface\)/);
        expect(rule(".btn.active")).not.toMatch(/--color-surface/);
    });

    it("keeps Button the only writer of the active class", () => {
        // A page hand-writing `class="btn active"` would drift the moment the
        // pressed look moves again.
        const btn = readFileSync(join(SRC, "components/ui/Button.tsx"), "utf8");
        expect(btn).toContain('c += " active"');
    });
});
