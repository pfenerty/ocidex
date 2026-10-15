// Fails the build if any compiled template carries a static style attribute.
//
// Solid compiles a JSX `style` whose value is known at build time into the
// template's HTML, and the browser parses it as an inline style attribute —
// which the web tier's CSP (web/nginx.conf, no 'unsafe-inline') blocks, so the
// style silently does not apply in production while every test passes. Styles
// computed at runtime go through element.style (CSSOM) and are unaffected.
// Use a class instead (ocidex-mqav.9).
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dir = new URL("../dist/assets/", import.meta.url).pathname;
const tag = /<[a-zA-Z][\w-]*\b[^<>]*?\sstyle=("[^"]*"|'[^']*'|[^\s>]+)[^<>]*>/g;

let found = 0;
for (const file of readdirSync(dir).filter((f) => f.endsWith(".js"))) {
    const src = readFileSync(join(dir, file), "utf8");
    for (const m of src.matchAll(tag)) {
        found++;
        console.error(`${file}: ${m[0].slice(0, 160)}`);
    }
}
if (found > 0) {
    console.error(
        `\n${found} static inline style attribute(s) in the build. The CSP blocks them; use a class instead (see web/scripts/check-inline-styles.mjs).`,
    );
    process.exit(1);
}
console.log("check-inline-styles: no static style attributes");
