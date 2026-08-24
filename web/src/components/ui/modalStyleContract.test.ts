import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "fs";
import { resolve, join } from "path";

/**
 * The `<dialog>` rules used to live in `pages/admin/SourcesTab.css`, imported
 * by one admin page. Every other Modal call site inherited them by accident,
 * and only because `App.tsx` imports all routes statically — the first
 * `lazy()` route would have left some dialogs unstyled while others were fine.
 *
 * A stylesheet that does nothing is not an assertion failure anywhere else in
 * the suite, so these two tests are what keep the rules attached to the
 * primitive that needs them (ocidex-ag4q.56).
 */
const SRC = resolve(__dirname, "../..");

function cssFiles(dir: string): string[] {
    return readdirSync(dir).flatMap((entry) => {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) return cssFiles(full);
        return full.endsWith(".css") ? [full] : [];
    });
}

describe("Modal style contract", () => {
    it("ships its own stylesheet and imports it", () => {
        const css = readFileSync(join(SRC, "components/ui/Modal.css"), "utf8");
        // The three properties without which a dialog is a browser-default box.
        expect(css).toMatch(/^dialog\s*\{/m);
        expect(css).toContain("background: var(--color-surface)");
        expect(css).toMatch(/dialog::backdrop/);

        const tsx = readFileSync(join(SRC, "components/ui/Modal.tsx"), "utf8");
        expect(tsx).toContain("Modal.css");
    });

    it("is the only stylesheet that styles a bare dialog element", () => {
        const offenders = cssFiles(SRC)
            .filter((f) => !f.endsWith("components/ui/Modal.css"))
            .filter((f) => /^\s*dialog(::?[\w-]+)?\s*(,|\{)/m.test(readFileSync(f, "utf8")))
            .map((f) => f.slice(SRC.length + 1));

        // A page-level file styling `dialog` means the primitive's appearance
        // depends on which route happened to load. Put the rule in Modal.css.
        expect(offenders).toEqual([]);
    });
});
