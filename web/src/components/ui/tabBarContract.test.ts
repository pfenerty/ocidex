import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const SRC = resolve(__dirname, "../..");

function tsxFiles(dir: string): string[] {
    return readdirSync(dir).flatMap((entry) => {
        const path = join(dir, entry);
        if (statSync(path).isDirectory()) return tsxFiles(path);
        return path.endsWith(".tsx") || path.endsWith(".ts") ? [path] : [];
    });
}

/**
 * The severity filter on /vulnerabilities was invisible for as long as it
 * existed: its markup emitted `tab-btn` / `tab-active`, and neither class is
 * defined anywhere in the stylesheet, so all six tabs computed identically
 * (ocidex-ag4q.6). Nothing failed — the classes were simply inert.
 *
 * TabBar exists to be the single writer of the real contract. These two tests
 * pin both halves of it: that the contract is still in the stylesheet, and that
 * no call site has drifted back to inventing its own class names.
 */
describe("tab-bar CSS contract", () => {
    it("still defines .tab-bar button.active", () => {
        const css = readFileSync(join(SRC, "index.css"), "utf-8");
        expect(css).toContain(".tab-bar button.active");
    });

    it("has no call site emitting the undefined tab-btn / tab-active classes", () => {
        // Comments are stripped first: this file and the call sites that were
        // converted both name the dead classes in prose, and that is not drift.
        const stripComments = (body: string) =>
            body.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

        const offenders = tsxFiles(SRC)
            .filter((path) => path !== __filename)
            .filter((path) => {
                const body = stripComments(readFileSync(path, "utf-8"));
                return body.includes("tab-btn") || body.includes("tab-active");
            });
        expect(offenders.map((p) => p.slice(SRC.length + 1))).toEqual([]);
    });
});
