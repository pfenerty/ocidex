import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

/**
 * Every internal link in the app must point at a route `App.tsx` declares.
 *
 * This is not hypothetical. `SBOMDetail`'s breadcrumb led with
 * `<A href="/sboms">SBOMs</A>` for as long as the page existed, and there has
 * never been a `/sboms` route — the crumb rendered the 404 page. Nothing caught
 * it because a wrong href is not a type error, is not a lint error, and reads as
 * completely correct in review.
 *
 * Only the static shape of a link is checked. An interpolated segment stands for
 * one path segment, which is what a `:param` route accepts, so an href built as
 * `/artifacts/` plus an id matches `/artifacts/:id`, and one built on `/nope/`
 * matches nothing.
 */

const SRC = new URL(".", import.meta.url).pathname;

/** Stands in for an interpolated segment on both sides of the comparison. */
const PARAM = "param";

function walk(dir: string): string[] {
    const out: string[] = [];
    for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name);
        if (e.isDirectory()) out.push(...walk(p));
        else if (e.name.endsWith(".tsx") && !e.name.endsWith(".test.tsx")) out.push(p);
    }
    return out;
}

function declaredRoutes(): string[] {
    const app = readFileSync(join(SRC, "App.tsx"), "utf8");
    return (
        [...app.matchAll(/<Route\s+path="([^"]+)"/g)]
            .map((m) => m[1])
            // The catch-all is the 404 page. Counting it as a destination would
            // make every href match and quietly turn this whole file into a
            // no-op — which it did on the first run, passing with a deliberate
            // `/sboms` link in the tree.
            .filter((r) => !r.startsWith("*"))
    );
}

/** A route pattern as a regex. A `:param` segment swallows one path segment. */
function routeMatcher(route: string): RegExp {
    const body = route
        .split("/")
        .map((seg) =>
            seg.startsWith(":")
                ? "[^/]+"
                : seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
        )
        .join("/");
    return new RegExp(`^${body}$`);
}

/** Internal hrefs, with interpolations reduced to a single-segment placeholder. */
function internalLinks(): { file: string; href: string }[] {
    const found: { file: string; href: string }[] = [];
    for (const file of walk(SRC)) {
        const source = readFileSync(file, "utf8");
        // Quoted hrefs and template-literal hrefs, matched separately so each
        // pattern has exactly one capture group. External links start with http,
        // and a bare anchor or a whole-expression href has no static shape to
        // check, so neither pattern sees them.
        for (const re of [/href="(\/[^"]*)"/g, /href=\{`(\/[^`]*)`\}/g]) {
            for (const m of source.matchAll(re)) {
                // Routes match on the path; drop the query string and hash.
                const path = m[1].split(/[?#]/)[0].replace(/\$\{[^}]*\}/g, PARAM);
                found.push({ file: file.slice(SRC.length), href: path });
            }
        }
    }
    return found;
}

describe("internal links point at declared routes", () => {
    const routes = declaredRoutes();
    const matchers = routes.map(routeMatcher);

    it("App.tsx declares the routes this test reads", () => {
        // A parse that silently found nothing would make the case below pass for
        // the wrong reason.
        expect(routes.length).toBeGreaterThan(15);
        expect(routes).toContain("/artifacts/:id");
    });

    it("has no link to a route that does not exist", () => {
        const dead = internalLinks()
            .filter(({ href }) => !matchers.some((re) => re.test(href)))
            .map((d) => `${d.file}: ${d.href.split(PARAM).join(":param")}`);
        expect([...new Set(dead)]).toEqual([]);
    });
});
