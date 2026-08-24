import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Every semantic foreground token must clear WCAG AA against the surfaces it
 * is actually painted on, in both themes.
 *
 * The light palette was built by copying the dark ladder position for position,
 * which works going *up* from #0C0E14 and does not work coming *down* from
 * white. The audit that produced this file (ocidex-ag4q.52) found nine tokens
 * failing that way at once — `--color-text-dim` at 2.93:1, success and warning
 * below 3.3 everywhere, `--color-elevated` sitting *below* the page background
 * so it was the darkest surface in a light theme — plus two tokens that fail
 * the same way in the dark theme, including white-on-light-blue for
 * `--color-secondary-fg`.
 *
 * None of that is a type error, a lint error, or visible in a screenshot to
 * anyone with good eyes and a bright monitor. It is only visible when measured,
 * so it is measured here: a swap of a hex for a "nicer" one now fails the
 * build with the ratio it would have shipped.
 *
 * Ratios are computed from the tokens as declared, so this checks the palette,
 * not any particular element. Per-element rendering was verified in the browser
 * across every route and tab panel in both themes.
 */

const CSS = readFileSync(join(__dirname, "index.css"), "utf-8");

/** WCAG 2.x relative luminance. */
function luminance([r, g, b]: number[]): number {
    const f = (v: number): number => {
        const c = v / 255;
        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

function contrast(fg: number[], bg: number[]): number {
    const [a, b] = [luminance(fg), luminance(bg)];
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

function hex(value: string): number[] {
    const h = value.trim().replace("#", "");
    const full = h.length === 3 ? [...h].map((c) => c + c).join("") : h;
    return [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16));
}

/**
 * The token block for one theme. Tailwind's `@theme` holds the dark defaults;
 * `.light` overrides a subset, so a light lookup falls back to the dark value
 * — exactly how the cascade resolves it in the browser.
 */
function palette(selector: string): Record<string, string> {
    const start = CSS.indexOf(`${selector} {`);
    if (start === -1) throw new Error(`no ${selector} block in index.css`);
    const body = CSS.slice(start, CSS.indexOf("\n}", start));
    const out: Record<string, string> = {};
    for (const m of body.matchAll(/(--[\w-]+):\s*(#[0-9A-Fa-f]{3,8})\s*;/g)) out[m[1]] = m[2];
    return out;
}

const dark = palette("@theme");
const light = { ...dark, ...palette(".light") };

const THEMES: [string, Record<string, string>][] = [
    ["dark", dark],
    ["light", light],
];

/**
 * The surfaces that carry body text. `--color-elevated` and
 * `--color-surface-hover` are deliberately excluded: elevated is a popover
 * ground (toast, command palette, combobox) and hover is a transient row
 * tint, and holding the dim greys to AA on those would mean collapsing
 * `--color-text-dim` into `--color-text-muted`. That trade is recorded at the
 * token rather than hidden here.
 */
const SURFACES = ["--color-bg", "--color-surface"];

/** Tokens painted as small text — the 4.5:1 threshold. */
const FOREGROUNDS = [
    "--color-text",
    "--color-text-muted",
    "--color-text-dim",
    "--color-secondary",
    "--color-success",
    "--color-warning",
    "--color-danger",
    "--color-accent-amber",
];

/**
 * Brand red is never small text. Its two text uses are the 2.5rem/700 wordmark
 * on the landing page and the same wordmark on login, which is WCAG "large"
 * and so takes the 3:1 threshold — the dark theme's #DC3545 measures 4.26 on
 * the page background, which passes there and would not pass as body copy.
 * --color-severity-critical is not a text colour at all: it is the deepest
 * step of the redscale in VulnBadge.css, where white sits *on* it (asserted in
 * ON_PAIRS below). Listing them here rather than dropping them keeps that
 * distinction stated instead of silently unchecked.
 */
const LARGE_FOREGROUNDS = ["--color-primary"];

/**
 * A foreground painted *on* a filled background. The `-fg` tokens name theirs
 * explicitly; `.sev-critical` in VulnBadge.css is white on the deepest step of
 * the severity redscale, which is the pairing that has no token to name it.
 */
const ON_PAIRS: [string, string][] = [
    ["--color-primary-fg", "--color-primary"],
    ["--color-secondary-fg", "--color-secondary"],
    ["--color-text", "--color-elevated"],
];

describe("palette contrast", () => {
    it("parses both themes", () => {
        // A silent parse failure would make every case below pass vacuously.
        expect(Object.keys(dark).length).toBeGreaterThan(20);
        expect(light["--color-bg"]).not.toBe(dark["--color-bg"]);
    });

    describe.each(THEMES)("%s theme", (_name, tokens) => {
        it.each(FOREGROUNDS)("%s clears 4.5:1 on every text surface", (fg) => {
            const value = tokens[fg];
            expect(value, `${fg} is not declared as a hex`).toBeDefined();
            for (const surface of SURFACES) {
                const ratio = contrast(hex(value), hex(tokens[surface]));
                expect(
                    +ratio.toFixed(2),
                    `${fg} (${value}) on ${surface} (${tokens[surface]})`,
                ).toBeGreaterThanOrEqual(4.5);
            }
        });

        it.each(LARGE_FOREGROUNDS)("%s clears 3:1 on every text surface", (fg) => {
            for (const surface of SURFACES) {
                const ratio = contrast(hex(tokens[fg]), hex(tokens[surface]));
                expect(
                    +ratio.toFixed(2),
                    `${fg} (${tokens[fg]}) on ${surface} (${tokens[surface]})`,
                ).toBeGreaterThanOrEqual(3);
            }
        });

        it("puts white on the deepest step of the severity redscale", () => {
            const ratio = contrast([255, 255, 255], hex(tokens["--color-severity-critical"]));
            expect(+ratio.toFixed(2)).toBeGreaterThanOrEqual(4.5);
        });

        it.each(ON_PAIRS)("%s clears 4.5:1 on %s", (fg, bg) => {
            const ratio = contrast(hex(tokens[fg]), hex(tokens[bg]));
            expect(
                +ratio.toFixed(2),
                `${fg} (${tokens[fg]}) on ${bg} (${tokens[bg]})`,
            ).toBeGreaterThanOrEqual(4.5);
        });

        // The light theme shipped --color-elevated *below* --color-bg, making
        // the popover ground the darkest surface in a light theme and pulling
        // every semantic token to its worst measurement against the one
        // surface that floats above everything. The direction is not the
        // invariant — a dark theme lightens to elevate and a light theme does
        // the reverse of whatever its cascade needs — so what is asserted is
        // the consequence: secondary text stays legible on a popover.
        it("keeps muted text legible on the popover ground", () => {
            const ratio = contrast(hex(tokens["--color-text-muted"]), hex(tokens["--color-elevated"]));
            expect(
                +ratio.toFixed(2),
                `--color-text-muted on --color-elevated (${tokens["--color-elevated"]})`,
            ).toBeGreaterThanOrEqual(4.5);
        });
    });
});
