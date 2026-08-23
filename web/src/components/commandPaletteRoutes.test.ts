// @vitest-environment node
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const read = (p: string): string => readFileSync(join(__dirname, "..", p), "utf8");

/**
 * The palette's entry list is hand-written (see the note above `ENTRIES`), which
 * buys readable names and search words at the cost of a second place to edit
 * when a route is added. This test is that cost made loud: add a parameterless
 * route to `App.tsx` and forget the palette, and the build fails here rather
 * than shipping a page the palette cannot reach.
 */
describe("command palette route coverage", () => {
    const app = read("App.tsx");
    const palette = read("components/CommandPalette.tsx");

    /** Every `<Route path="...">` in App.tsx. */
    const declared = Array.from(app.matchAll(/<Route\s+path="([^"]+)"/g)).map((m) => m[1]);

    /** Routes a user could actually be sent to with no further input. */
    const reachable = declared.filter(
        (p) =>
            !p.includes(":") && // needs an id the palette does not have
            !p.endsWith("/lookup") && // ADR-042 resolvers, not destinations
            !p.startsWith("*"), // the 404 catch-all
    );

    const entryPaths = Array.from(palette.matchAll(/path: "([^"]+)"/g)).map((m) => m[1]);

    it("finds the routes it is asserting about", () => {
        expect(declared.length).toBeGreaterThan(20);
        expect(reachable).toContain("/vulnerabilities");
        expect(entryPaths.length).toBeGreaterThan(10);
    });

    it("offers every parameterless route", () => {
        // /admin bare renders whichever tab the user may see, and each of those
        // tabs has its own entry — listing the bare path as well would put a
        // duplicate destination in the list under a vaguer name.
        const exempt = new Set(["/admin", "/admin/registries"]);
        const missing = reachable.filter((p) => !exempt.has(p) && !entryPaths.includes(p));
        expect(missing).toEqual([]);
    });

    it("points every entry at a route that exists", () => {
        const dangling = entryPaths.filter((p) => !declared.includes(p));
        expect(dangling).toEqual([]);
    });
});
