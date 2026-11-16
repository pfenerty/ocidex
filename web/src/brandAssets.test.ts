import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// One mark, drawn once (ocidex-iz0r.1). Before this the app favicon, the docs logo and
// the sidebar each carried a different "OD" set as live SVG <text>, which every OS
// rendered in its own fallback font. The copies below are served by different hosts
// (vite public/, Astro public/ and assets/), so they cannot import one file; this test
// keeps them byte-identical instead.
const root = join(__dirname, "..", "..");
const read = (p: string) => readFileSync(join(root, p), "utf-8");
const canonical = read("web/public/brand/mark.svg");

describe("brand mark assets", () => {
    it.each(["web/public/favicon.svg", "site/public/favicon.svg", "site/src/assets/logo.svg"])(
        "%s is a byte-identical copy of web/public/brand/mark.svg",
        (path) => {
            expect(read(path)).toBe(canonical);
        },
    );

    it("is drawn from paths, never live text", () => {
        expect(canonical).not.toMatch(/<text[\s>]/);
    });

    it("BrandMark.tsx draws the same geometry as the canonical file", () => {
        const component = read("web/src/components/BrandMark.tsx");
        const d = /\sd="([^"]+)"/.exec(canonical)?.[1];
        expect(d).toBeDefined();
        expect(component).toContain(d);
    });
});
