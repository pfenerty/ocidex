import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

/**
 * The red/blue split documented in index.css (ocidex-ag4q.11).
 *
 *   red  (--color-brand)     identity only (the mark's LED)
 *   ink  (--color-ink)       the one primary action
 *   blue (--color-secondary) navigation and state
 *
 * Nothing in the type system or the linter can tell those apart, and the whole
 * failure mode this replaces was the two tokens drifting into interchangeable
 * use over 47 call sites. So the rule is asserted here: the specific places
 * that were wrong stay fixed, and any *new* red outside the allowed brand
 * surfaces fails the build rather than quietly re-blurring the split.
 */

const SRC = __dirname;

function read(rel: string): string {
    return readFileSync(join(SRC, rel), "utf-8");
}

/** Every .css/.tsx under src, so a new file cannot slip past the sweep. */
function sources(dir = SRC, acc: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) sources(full, acc);
        else if (/\.(css|tsx)$/.test(entry) && !entry.endsWith(".test.tsx")) acc.push(full);
    }
    return acc;
}

// Where brand red is legitimate: OCIDex's own chrome. index.css is exempt
// because it defines the tokens. The shell and header stories of ocidex-iz0r
// shrink this list to the mark itself.
const BRAND_FILES = [
    "index.css",
    "components/Layout.css",
    "components/Feedback.css",
    "pages/Home.css",
    "pages/Login.tsx",
];

describe("brand red stays on brand surfaces", () => {
    it("is not reachable from any other file", () => {
        const offenders = sources()
            .filter((f) => !BRAND_FILES.some((b) => f.endsWith(b)))
            .filter((f) => readFileSync(f, "utf-8").includes("--color-brand"))
            .map((f) => f.slice(SRC.length + 1));
        expect(offenders).toEqual([]);
    });
});

describe("the primary action is ink, not brand red", () => {
    // ocidex-iz0r.2: every CTA was brand red, so its disabled state was a muddy
    // maroon and a view with two CTAs had two competing reds.
    it.each([".btn-primary {", ".btn-primary:hover {"])("index.css: %s", (selector) => {
        const css = read("index.css");
        const at = css.indexOf(selector);
        expect(at, `no rule ${selector}`).toBeGreaterThan(-1);
        const body = css.slice(at, css.indexOf("}", at));
        expect(body).toContain("--color-ink");
        expect(body).not.toContain("--color-brand");
    });
});

describe("navigation and state read blue", () => {
    // Each of these shipped red, so red marked "where you are" with exactly the
    // same colour as "this deletes something".
    it.each([
        ["index.css", ".tab-bar button.active"],
        ["components/TileBand.css", ".tile.active"],
        ["components/Layout.css", ".sidebar nav a.active"],
        ["components/ThemeToggle.css", ".theme-icon.active"],
    ])("%s: %s", (file, selector) => {
        const css = read(file);
        const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        // The selector may be one of several in a comma-separated list — the
        // tab strip styles `button` and `a` together — so anything up to the
        // opening brace that is still part of the same selector list counts.
        const m = new RegExp(`${escaped}[^{}]*\\{([^}]*)\\}`).exec(css);
        if (m === null) throw new Error(`no rule for ${selector} in ${file}`);
        expect(m[1]).toContain("--color-secondary");
        expect(m[1]).not.toContain("--color-brand");
    });
});

describe("status vocabularies do not borrow the brand", () => {
    it("gives critical severity its own token", () => {
        // Otherwise restyling the brand silently restyles the top of the
        // severity scale, which is a different thing that happens to be red.
        expect(read("components/VulnBadge.css")).toContain("--color-severity-critical");
        expect(read("index.css")).toMatch(/--color-severity-critical:\s*#[0-9A-Fa-f]{6}/);
    });

    it("names every job state with a semantic token", () => {
        const cells = read("pages/admin/jobs/jobCells.tsx");
        const states = /JOB_STATE_COLORS[^}]*}/.exec(cells)?.[0] ?? "";
        expect(states).not.toContain("--color-brand");
        // --color-error has never been defined; it was falling through to a
        // hardcoded hex fallback that no theme could override.
        expect(states).not.toContain("--color-error");
    });
});

describe("--color-info", () => {
    it("aliases --color-secondary rather than repeating its hex", () => {
        // Two names for one colour is how they end up as two colours.
        const matches = [...read("index.css").matchAll(/--color-info:\s*([^;]+);/g)].map(
            (m) => m[1].trim(),
        );
        expect(matches.length).toBeGreaterThan(0);
        expect(matches.every((v) => v === "var(--color-secondary)")).toBe(true);
    });
});
