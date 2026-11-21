import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/**
 * A URL that came from data (an SBOM, an image label, an advisory) reaches an
 * href only through safeHref, directly or via <ExternalAnchor url={…}>. Those
 * strings are written by whoever built the image, and a `javascript:` href runs
 * script on click wherever the CSP doesn't stop it.
 *
 * The rule is a heuristic on names: an `href={…}` expression that mentions a
 * url must be a safeHref(…) call, an UPPER_CASE constant, or a template literal
 * that fixes its own scheme or path (`/…`, `https://…`, `${API_BASE_URL}…`).
 */
const SRC = __dirname;

function code(file: string): string {
    return readFileSync(file, "utf-8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/[^\n]*/g, "");
}

function sources(dir: string, acc: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) sources(full, acc);
        else if (full.endsWith(".tsx") && !full.endsWith(".test.tsx")) acc.push(full);
    }
    return acc;
}

const HREF = /\bhref=\{\s*([^}]*)/g;
const SAFE = [/^safeHref\(/, /^[A-Z][A-Z0-9_]*$/, /^`(\/|https:\/\/|\$\{API_BASE_URL)/];

describe("external links", () => {
    it("send every url-named href through safeHref", () => {
        const offenders: string[] = [];
        for (const f of sources(SRC)) {
            for (const m of code(f).matchAll(HREF)) {
                const expr = m[1].trim();
                if (!/url/i.test(expr)) continue;
                if (SAFE.some((re) => re.test(expr))) continue;
                offenders.push(`${relative(SRC, f)}: href={${expr}`);
            }
        }
        expect(offenders).toEqual([]);
    });
});
