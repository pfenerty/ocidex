import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const index = readFileSync(join(__dirname, "index.css"), "utf-8");
const layout = readFileSync(join(__dirname, "components/Layout.css"), "utf-8");

const STEPS = ["xs", "sm", "base", "lg", "xl", "2xl", "3xl"] as const;

function token(name: string): number {
    const m = new RegExp(`--text-${name}:\\s*([0-9.]+)rem`).exec(index);
    if (m === null) throw new Error(`--text-${name} is not defined`);
    return Number(m[1]);
}

// Every declaration block this selector participates in, concatenated — a
// selector may be styled once on its own and once inside a grouped rule, and
// either is a legitimate place for the font-size to come from.
function rule(css: string, selector: string): string {
    const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const blocks = [
        ...css.matchAll(new RegExp(`(?:^|[},])\\s*${escaped}\\s*[,{]`, "gm")),
    ].map((m) => {
        const open = css.indexOf("{", m.index + m[0].length - 1);
        return css.slice(open + 1, css.indexOf("}", open));
    });
    if (blocks.length === 0) throw new Error(`no rule for ${selector}`);
    return blocks.join("\n");
}

describe("type scale", () => {
    it("defines every step", () => {
        for (const s of STEPS) expect(token(s)).toBeGreaterThan(0);
    });

    it("is strictly increasing", () => {
        const sizes = STEPS.map(token);
        expect(sizes).toEqual([...sizes].sort((a, b) => a - b));
        expect(new Set(sizes).size).toBe(sizes.length);
    });

    // These three back Tailwind's text-xs/text-sm/text-base utilities, which
    // Tailwind v4 generates from this token namespace. There are 70 `text-sm`
    // call sites; retuning the token would silently move all of them, so the
    // widening is confined to the heading end of the scale.
    it("leaves the body end of the scale at Tailwind's defaults", () => {
        expect(token("xs")).toBe(0.75);
        expect(token("sm")).toBe(0.875);
        expect(token("base")).toBe(1);
    });

    it("separates page titles from card titles by a real step", () => {
        expect(token("3xl") / token("lg")).toBeGreaterThan(1.5);
    });
});

describe("headings are sized from the scale, not from literals", () => {
    it.each(["h1", "h2", "h3", "h4"])("%s", (h) => {
        expect(rule(index, h)).toMatch(/font-size:\s*var\(--text-/);
    });

    it(".card-header h3", () => {
        expect(rule(index, ".card-header h3")).toMatch(/font-size:\s*var\(--text-/);
    });

    it(".page-header h2", () => {
        expect(rule(layout, ".page-header h2")).toMatch(/font-size:\s*var\(--text-/);
    });
});
