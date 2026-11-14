// Prefixes root-relative markdown links ("/guides/...") with Astro's `base`, so pages can
// link absolutely (which starlight-links-validator checks) and still work in the /next/
// preview build. With base "/" it is a no-op.
export function remarkBaseLinks(base) {
  const prefix = base.replace(/\/+$/, "");
  const walk = (node) => {
    if ((node.type === "link" || node.type === "definition") && typeof node.url === "string") {
      if (prefix && node.url.startsWith("/") && !node.url.startsWith("//") && !node.url.startsWith(prefix + "/")) {
        node.url = prefix + node.url;
      }
    }
    for (const child of node.children ?? []) walk(child);
  };
  return () => (tree) => walk(tree);
}
