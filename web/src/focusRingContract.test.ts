import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

/**
 * The keyboard ring (ocidex-ag4q.51).
 *
 * One bare `:focus-visible` rule in index.css rings everything the browser
 * considers focusable, so a new primitive is covered the moment it renders and
 * nobody has to remember it. That generality is also the fragility: the rule is
 * a single line, it has the weakest specificity in the app, and *any*
 * `outline: none` that outranks it silently deletes the ring for whatever it
 * covers — with nothing failing, because a control with no focus style still
 * clicks fine and still passes every behavioural test.
 *
 * So the two halves are asserted separately: the rule exists and reads the
 * token, and every opt-out is accounted for by name.
 */
const SRC = __dirname;
const indexCss = readFileSync(join(SRC, "index.css"), "utf-8");

function stylesheets(dir = SRC, acc: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) stylesheets(full, acc);
        else if (entry.endsWith(".css")) acc.push(full);
    }
    return acc;
}

/** Strip comments so a rule quoted in prose is not mistaken for a declaration. */
function code(css: string): string {
    return css.replace(/\/\*[\s\S]*?\*\//g, "");
}

describe("focus ring", () => {
    it("defines --color-focus once, as an alias rather than a fourth blue", () => {
        const decls = [...code(indexCss).matchAll(/--color-focus:\s*([^;]+);/g)].map((m) => m[1].trim());
        expect(decls).toEqual(["var(--color-secondary)"]);
    });

    it("rings everything focusable from one bare rule", () => {
        // Bare `:focus-visible`, not a list of selectors: a list is a thing to
        // forget, and the forgetting is invisible.
        const rule = /(^|[;}])\s*:focus-visible\s*\{([^}]*)\}/m.exec(code(indexCss));
        if (rule === null) throw new Error("index.css has no bare :focus-visible rule");
        expect(rule[2]).toMatch(/outline:\s*2px solid var\(--color-focus\)/);
        // An outline, not a box-shadow: it follows border-radius, is not clipped
        // by an ancestor's overflow, and survives forced-colors mode.
        expect(rule[2]).not.toMatch(/box-shadow/);
    });

    it("keeps the ring reachable — no unaccounted `outline: none`", () => {
        // Each entry is a control that supplies its own focus affordance and
        // says so in its stylesheet. Adding a file here is a decision; leaving
        // one out is how the ring disappears.
        const ALLOWED = new Set([
            // Text fields ring via their border and halo, on :focus rather than
            // :focus-visible, so a click shows which field has the caret.
            "index.css",
            // A badge-shaped trigger; rings as a pill via box-shadow instead.
            "components/ui/Tooltip.css",
            // The palette's single input holds focus for the panel's whole
            // life, so a ring there marks nothing.
            "components/CommandPalette.css",
        ]);
        const offenders = stylesheets()
            .filter((f) => /outline:\s*none/.test(code(readFileSync(f, "utf-8"))))
            .map((f) => f.slice(SRC.length + 1))
            .filter((rel) => !ALLOWED.has(rel));
        expect(offenders).toEqual([]);
    });

    it("halos a focused field in the current theme's blue, not a baked-in hex", () => {
        // The literal here was the dark palette's #5B8DEF as rgba(), so a
        // focused field in light mode was haloed in the wrong blue.
        const halo = /textarea:focus\s*\{([^}]*)\}/.exec(code(indexCss));
        if (halo === null) throw new Error("no focused-field rule");
        expect(halo[1]).toMatch(/box-shadow:[^;]*var\(--color-focus\)/);
        expect(halo[1]).not.toMatch(/rgba?\(/);
    });
});
