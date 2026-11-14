// Pages link root-relative ("/guides/..."), so starlight-links-validator can check every link
// at base "/". For the /next/ preview (DOCS_BASE=/next/) this rewrites those links in the built
// HTML, which covers markdown links, hero actions and LinkCards alike. Astro's own asset URLs
// already carry the base and are left alone. With base "/" it does nothing.
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export function baseLinks(base) {
  const prefix = base.replace(/\/+$/, "");
  return {
    name: "ocidex-base-links",
    hooks: {
      "astro:build:done": async ({ dir }) => {
        if (!prefix) return;
        const root = fileURLToPath(dir);
        const attr = new RegExp(`(href|src)="/(?!/|${prefix.slice(1)}/)`, "g");
        for (const file of await readdir(root, { recursive: true })) {
          if (!file.endsWith(".html")) continue;
          const path = join(root, file);
          const html = await readFile(path, "utf8");
          const out = html.replace(attr, `$1="${prefix}/`);
          if (out !== html) await writeFile(path, out);
        }
      },
    },
  };
}
