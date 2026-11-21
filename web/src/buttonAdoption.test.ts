import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const SRC = __dirname;

describe("the bare <button> element carries no look", () => {
    /**
     * The `button { … }` rule in index.css, comments stripped, or the prose
     * explaining it counts as a declaration.
     */
    function baseButtonRule(): string {
        const css = readFileSync(join(SRC, "index.css"), "utf-8").replace(/\/\*[\s\S]*?\*\//g, "");
        const m = /^\s*button\s*\{([^}]*)\}/m.exec(css);
        if (m === null) throw new Error("no bare `button` rule in index.css");
        return m[1];
    }

    function properties(block: string): string[] {
        return block
            .split(";")
            .map((d) => d.split(":")[0].trim())
            .filter((p) => p.length > 0)
            .sort();
    }

    it("declares an affordance and nothing else", () => {
        // The rule used to carry fifteen declarations identical, property for
        // property, to `.btn` (ocidex-ag4q.54): every native button in the app
        // was a secondary button by default, so a control could opt into the
        // house style by writing no class, and four other classes had to open
        // with the same reset to opt back out. `cursor` stays because Tailwind
        // v4's preflight resets font, colour, border and background on form
        // elements but deliberately leaves the cursor alone.
        expect(properties(baseButtonRule())).toEqual(["cursor"]);
    });

    it("keeps the look on .btn, where <Button> can reach it", () => {
        const css = readFileSync(join(SRC, "index.css"), "utf-8").replace(/\/\*[\s\S]*?\*\//g, "");
        const m = /^\s*\.btn\s*\{([^}]*)\}/m.exec(css);
        if (m === null) throw new Error("no `.btn` rule in index.css");
        const props = properties(m[1]);
        for (const p of ["padding", "border", "border-radius", "background", "color", "font-size"]) {
            expect(props).toContain(p);
        }
    });
});
