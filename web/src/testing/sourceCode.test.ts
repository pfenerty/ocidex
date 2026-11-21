import { describe, it, expect } from "vitest";
import { stripComments } from "./sourceCode";

describe("stripComments", () => {
    it("removes line and block comments", () => {
        expect(stripComments("a // gone\nb /* gone */ c", "x.ts")).toBe("a  \nb   c");
    });

    it("keeps // inside strings, so code after a URL is still checked", () => {
        const src = `const a = <a href="https://example.com" class="btn">x</a>; // note`;
        const out = stripComments(src);
        expect(out).toContain(`class="btn"`);
        expect(out).toContain(`"https://example.com"`);
        expect(out).not.toContain("note");
    });

    it("keeps // inside template literals", () => {
        expect(stripComments("const u = `https://${host}/x`; // c", "x.ts")).toContain("`https://${host}/x`");
    });

    it("keeps line numbers for multi-line comments", () => {
        expect(stripComments("a\n/* one\ntwo */\nb", "x.ts").split("\n")).toHaveLength(4);
    });
});

describe("stripComments in JSX", () => {
    it("reads an apostrophe in JSX text as text, not a string", () => {
        const src = "const a = <p>can't stop</p>;\n/** Usually a `.btn-group`. */\nconst b = 1;";
        const out = stripComments(src);
        expect(out).not.toContain("btn-group");
        expect(out).toContain("can't stop");
    });

    it("keeps // in JSX text and strips {/* */} JSX comments", () => {
        const out = stripComments("const a = <p>see https://x.y {/* hidden */}</p>;");
        expect(out).toContain("https://x.y");
        expect(out).not.toContain("hidden");
    });
});
