import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const css = readFileSync(join(__dirname, "index.css"), "utf-8");

// The first family in a --font-* token is the one the design intends; the rest
// are OS fallbacks. If it is never fetched the token still resolves — silently,
// to the fallback — which is exactly how Inter and JetBrains Mono were declared
// for the whole app while never rendering anywhere (ocidex-ag4q.9).
function declaredFamilies(): string[] {
    const families = new Set<string>();
    for (const [, value] of css.matchAll(/--font-[a-z]+:\s*([^;]+);/g)) {
        const first = /"([^"]+)"/.exec(value);
        if (first !== null) families.add(first[1]);
    }
    return [...families];
}

function requestedFamilies(): string[] {
    const link = /@import url\("(https:\/\/fonts\.googleapis\.com[^"]+)"\)/.exec(css);
    if (link === null) return [];
    return [...link[1].matchAll(/family=([^:&]+)/g)].map((m) =>
        decodeURIComponent(m[1]).replace(/\+/g, " "),
    );
}

describe("font tokens and the stylesheet request agree", () => {
    it("declares at least the three families the design uses", () => {
        expect(declaredFamilies().sort()).toEqual(["Inter", "JetBrains Mono", "Space Grotesk"]);
    });

    it("fetches every family a --font-* token names first", () => {
        const requested = requestedFamilies();
        expect(declaredFamilies().filter((f) => !requested.includes(f))).toEqual([]);
    });

    it("swaps rather than blocking paint", () => {
        expect(css).toContain("display=swap");
    });
});
