// @ts-check
// OCIDex public docs site (ADR-0057). `/` documents the latest release; main publishes a
// preview under `/next/`, which the push pipeline builds with DOCS_BASE=/next/.
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import starlightLinksValidator from "starlight-links-validator";
import { remarkBaseLinks } from "./src/plugins/remark-base-links.mjs";

const base = process.env.DOCS_BASE ?? "/";
const isNext = base.replace(/\/+$/, "") === "/next";

export default defineConfig({
  site: "https://docs.ocidex.app",
  base,
  trailingSlash: "always",
  markdown: { remarkPlugins: [remarkBaseLinks(base)] },
  integrations: [
    starlight({
      title: "OCIDex",
      description:
        "OCIDex stores, enriches and diffs the SBOMs of your container images, so you can answer what is running, what changed and what is vulnerable.",
      logo: { src: "./src/assets/logo.svg", replacesTitle: false },
      favicon: "/favicon.svg",
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/pfenerty/ocidex" }],
      editLink: { baseUrl: "https://github.com/pfenerty/ocidex/edit/main/site/" },
      lastUpdated: true,
      customCss: ["./src/styles/custom.css"],
      // Every internal link is checked at build time; a broken one fails the build. Pages
      // link root-relative ("/guides/..."); the validator checks those at base "/" (the PR
      // build and the release build), and remarkBaseLinks prefixes them for /next/. Relative
      // links are rejected because the validator cannot check them.
      plugins: isNext ? [] : [starlightLinksValidator({ errorOnLocalLinks: true })],
      components: isNext ? { Banner: "./src/components/NextBanner.astro" } : {},
      sidebar: [
        { label: "Get started", items: [{ autogenerate: { directory: "getting-started" } }] },
        { label: "Concepts", items: [{ autogenerate: { directory: "concepts" } }] },
        {
          label: "Guides",
          items: [
            { label: "Operate", items: [{ autogenerate: { directory: "guides/operate" } }] },
            { label: "Use", items: [{ autogenerate: { directory: "guides/use" } }] },
            { label: "Integrate", items: [{ autogenerate: { directory: "guides/integrate" } }] },
          ],
        },
        { label: "Reference", items: [{ autogenerate: { directory: "reference" } }] },
      ],
    }),
  ],
});
