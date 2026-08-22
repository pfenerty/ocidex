import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// Comments are stripped, or these assertions read the prose explaining a rule
// instead of the rule: the .main-content cap's own comment names
// `margin-inline: auto`, which made the centring assertion pass with the
// declaration deleted.
function declarations(path: string): string {
    return readFileSync(join(__dirname, path), "utf-8").replace(/\/\*[\s\S]*?\*\//g, "");
}

const index = declarations("index.css");
const layout = declarations("components/Layout.css");

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

describe("the reading column is bounded", () => {
    // Measured at a 2200px window before this cap: 1220px of content spread
    // across the full field, so a table row put its first and last cell a
    // screen apart. A width no rule states is a width nothing keeps.
    const main = rule(layout, ".main-content");

    it("caps .main-content", () => {
        const m = /max-width:\s*(\d+)px/.exec(main);
        expect(m).not.toBeNull();
        // Wide enough for the app's widest table -- admin Sources, 9 columns --
        // without turning the cap itself into the thing that clips content.
        expect(Number(m?.[1])).toBeGreaterThanOrEqual(1400);
    });

    it("centres it rather than pinning it left", () => {
        expect(main).toMatch(/margin-inline:\s*auto/);
    });

    it("still scrolls anything wider inside the column", () => {
        // The cap must not become a clip: a table that exceeds it scrolls here
        // instead of stretching the page.
        expect(main).toMatch(/overflow-x:\s*auto/);
    });
});
