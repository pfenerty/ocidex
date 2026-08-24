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

    it("defines .filter-chips as a visually distinct control, not an alias", () => {
        // A filter strip and a nav strip look identical unless the chip rules
        // actually differ from the tab rules (ocidex-ag4q.44). Asserting the
        // class exists is not enough — `.filter-chips { }` would pass that and
        // render as an unstyled row of bare buttons.
        const css = readFileSync(join(SRC, "index.css"), "utf-8");
        expect(css).toContain(".filter-chips button.active");

        // Comments are stripped so prose naming a selector cannot stand in for
        // a rule, and the selector is anchored to the start of its line so
        // `.tab-bar` cannot match the `.tab-bar button` rule below it.
        const body = css.replace(/\/\*[\s\S]*?\*\//g, "");
        const rule = (selector: string): string => {
            const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            const match = new RegExp(`^\\s*${escaped}[^{}]*\\{([^}]*)\\}`, "m").exec(body);
            if (match === null) throw new Error(`no rule for ${selector}`);
            return match[1];
        };

        // The whole point is shape: pills are separately outlined and rounded,
        // where tabs share one baseline rule.
        expect(rule(".filter-chips button,")).toMatch(/border-radius:\s*999px/);
        expect(rule(".filter-chips button,")).toMatch(/border:\s*1px solid/);
        expect(rule(".tab-bar")).toMatch(/border-bottom:/);
        expect(rule(".filter-chips")).not.toMatch(/border-bottom:/);

        // Active is blue on both. The difference is shape, not hue, per the
        // token split documented at the top of index.css.
        expect(rule(".filter-chips button.active,")).toMatch(/--color-secondary/);
        expect(rule(".filter-chips button.active,")).not.toMatch(/--color-primary/);
    });

    it("routes every filter strip through the filter variant", () => {
        // These four narrow the list already on screen. If one loses
        // `variant="filter"` it silently renders as navigation again.
        const filters = [
            "pages/Vulnerabilities.tsx",
            "pages/Licenses.tsx",
            "pages/ClusterDetail/VulnerabilitiesTab.tsx",
            "pages/ArtifactVersionHistory.tsx",
            "pages/ArtifactDetail/ChangelogTab.tsx",
        ];
        const missing = filters.filter(
            (rel) => !readFileSync(join(SRC, rel), "utf-8").includes('variant="filter"'),
        );
        expect(missing).toEqual([]);
    });

    it("leaves no page hand-rolling the tab-bar markup", () => {
        // TabBar is the single writer of both strips, so a variant added later
        // reaches every call site rather than the ones someone remembered.
        const offenders = tsxFiles(SRC)
            .filter((path) => path !== __filename)
            .filter((path) => /class="(tab-bar|filter-chips)\b/.test(readFileSync(path, "utf-8")))
            .map((p) => p.slice(SRC.length + 1));
        expect(offenders).toEqual([]);
    });

    it("gives the mobile strip something to scroll", () => {
        // `overflow-x: auto` on a flex row is inert on its own: the items
        // shrink below their content and wrap their labels instead of
        // overflowing, so the container never has a scrollable width
        // (ocidex-ag4q.59). The two declarations that make it real live on the
        // items, not the container, which is exactly the pairing a later edit
        // is likely to split up.
        const css = readFileSync(join(SRC, "index.css"), "utf-8").replace(/\/\*[\s\S]*?\*\//g, "");
        const start = css.indexOf("@media (max-width: 768px)");
        expect(start).toBeGreaterThanOrEqual(0);

        let depth = 0;
        let block = "";
        for (let i = css.indexOf("{", start); i < css.length; i++) {
            if (css[i] === "{") depth++;
            else if (css[i] === "}" && --depth === 0) {
                block = css.slice(css.indexOf("{", start) + 1, i);
                break;
            }
        }
        expect(block).not.toBe("");

        const itemRule = /\.tab-bar button,\s*\.tab-bar a\s*\{([^}]*)\}/.exec(block);
        if (itemRule === null) throw new Error("no mobile rule for the tab-bar items");
        expect(itemRule[1]).toMatch(/flex-shrink:\s*0/);
        expect(itemRule[1]).toMatch(/white-space:\s*nowrap/);
        expect(block).toMatch(/\.tab-bar\s*\{[^}]*overflow-x:\s*auto/);
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
