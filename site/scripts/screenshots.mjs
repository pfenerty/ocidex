// Captures the docs site's screenshots from a running OCIDex (ocidex-mxy0.9, ADR-0057), so
// the pictures track the UI instead of going stale. Run it against the dev-auth rig
// (`make dev-auth-up` and `make frontend-dev-auth`), which seeds a cluster, vulnerabilities
// and signing states, at a fixed viewport and theme:
//
//   OCIDEX_UI_URL=http://localhost:3200 OCIDEX_API_KEY=ocidex_... \
//     npm run screenshots              # from site/, or `make docs-screenshots`
//
// What it shoots is found through the API, not hard-coded: the artifact with the most
// SBOMs, two versions of one architecture for the diff, the library in the most SBOMs, the first
// cluster. Output: src/assets/screenshots/<name>.png. Commit the result.
//
// The API key is attached only to same-origin /api and /auth requests, never to anything
// else the page loads (fonts, for one), and only ever needs read access.
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const ui = (process.env.OCIDEX_UI_URL ?? "http://localhost:3000").replace(/\/+$/, "");
const key = process.env.OCIDEX_API_KEY;
const theme = process.env.OCIDEX_THEME ?? "light";
const outDir = join(dirname(fileURLToPath(import.meta.url)), "../src/assets/screenshots");
const viewport = { width: 1440, height: 900 };

if (!key) {
  console.error("OCIDEX_API_KEY is required: a read-only key on the instance at " + ui);
  process.exit(2);
}

async function api(path) {
  const res = await fetch(ui + path, { headers: { Authorization: `Bearer ${key}` } });
  if (!res.ok) throw new Error(`GET ${path}: ${res.status} ${await res.text()}`);
  return res.json();
}

// Pick the subjects through the API, so the script works on any seeded instance.
async function subjects() {
  const artifacts = (await api("/api/v1/artifacts?limit=100")).data ?? [];
  if (artifacts.length === 0) throw new Error("no artifacts: seed the instance first");
  const artifact = artifacts.reduce((a, b) => ((b.sbomCount ?? 0) > (a.sbomCount ?? 0) ? b : a));
  // Newest first. The diff wants two versions of one architecture and flavor: across
  // architectures every package reads as removed and added. Take the newest series
  // that has two versions.
  const all = (await api(`/api/v1/artifacts/${artifact.id}/sboms?limit=100`)).data ?? [];
  let sboms = all.slice(0, 1);
  for (const newest of all) {
    const previous = all.find(
      (s) =>
        s.architecture === newest.architecture &&
        s.flavor === newest.flavor &&
        s.subjectVersion !== newest.subjectVersion,
    );
    if (previous) {
      sboms = [newest, previous];
      break;
    }
  }
  const [pkg] =
    (await api("/api/v1/components/distinct?type=library&sort=sbomCount&sortDir=desc&limit=1"))
      .data ?? [];
  const clusters = (await api("/api/v1/clusters")).data ?? [];
  return { artifact, sboms, pkg, cluster: clusters[0] };
}

function shots({ artifact, sboms, pkg, cluster }) {
  const list = [
    { name: "home", path: "/" },
    { name: "artifact", path: `/artifacts/${artifact.id}` },
    { name: "changelog", path: `/artifacts/${artifact.id}?tab=changelog` },
    { name: "vulnerabilities", path: `/artifacts/${artifact.id}?tab=vulns` },
    { name: "vulnerability-list", path: "/vulnerabilities" },
    { name: "licenses", path: "/licenses" },
  ];
  // The docs import every one of these, so a missing subject is an error, not a skip:
  // a stale picture left behind would pass for a current one.
  if (sboms.length < 2) throw new Error(`${artifact.name} has no two versions of one architecture to diff`);
  if (!pkg) throw new Error("no library components to show");
  if (!cluster) throw new Error("no clusters: register one and push an inventory");
  list.push(
    { name: "sbom", path: `/sboms/${sboms[0].id}` },
    { name: "diff", path: `/diff?from=${sboms[1].id}&to=${sboms[0].id}` },
    { name: "package", path: `/components/overview?name=${encodeURIComponent(pkg.name)}` },
    { name: "cluster", path: `/clusters/${cluster.id}` },
  );
  return list;
}

const targets = shots(await subjects());
await mkdir(outDir, { recursive: true });

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport,
  deviceScaleFactor: 2,
  colorScheme: theme,
  reducedMotion: "reduce",
});
await context.addInitScript((t) => {
  try {
    localStorage.setItem("ocidex-theme", t);
  } catch {
    // Storage can be unavailable; the colorScheme above still applies.
  }
}, theme);
for (const prefix of ["/api/", "/auth/"]) {
  await context.route(`${ui}${prefix}**`, (route) =>
    route.continue({ headers: { ...route.request().headers(), authorization: `Bearer ${key}` } }),
  );
}

// Dev-only chrome, like the dev-auth rig's persona switcher, never belongs in a docs picture.
const hideDevChrome = '[data-testid="persona-switcher"] { display: none !important; }';

const page = await context.newPage();
for (const { name, path } of targets) {
  await page.goto(ui + path, { waitUntil: "networkidle" });
  await page.addStyleTag({ content: hideDevChrome });
  await page.evaluate(() => document.fonts.ready);
  // Let skeletons resolve and charts finish their first layout.
  await page.waitForTimeout(500);
  const file = join(outDir, `${name}.png`);
  await page.screenshot({ path: file });
  console.log(`${name}: ${path}`);
}

await browser.close();
