import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { describe, it } from "node:test";

// Main-build chart versions must outrank the latest release, or Flux's ">=0.0.0-0" range on
// ocidex-dev keeps the release and stops following main (ocidex-sijt).

const repoRoot = path.join(__dirname, "..", "..");
const publishSh = readFileSync(path.join(__dirname, "..", "jobs", "helm-publish", "publish.sh"), "utf8");
const charts = ["ocidex", "ocidex-operator", "ocidex-k8s-agent"];

function chartVersion(chart: string): string {
  const yaml = readFileSync(path.join(repoRoot, "charts", chart, "Chart.yaml"), "utf8");
  const m = /^version: (\S+)$/m.exec(yaml);
  if (!m) throw new Error(`${chart}: no version in Chart.yaml`);
  return m[1];
}

// Runs publish.sh's own BASE_VERSION line for a given chart version.
function mainBase(chartVersion: string): string {
  const line = publishSh.split("\n").find((l) => l.startsWith("BASE_VERSION="));
  if (!line) throw new Error("publish.sh has no BASE_VERSION= line");
  return execFileSync("sh", ["-c", `CHART_VERSION='${chartVersion}'\n${line}\necho "$BASE_VERSION"`], {
    encoding: "utf8",
  }).trim();
}

// Semver precedence, enough for X.Y.Z[-pre.ids]: cores numerically, then a prerelease sorts
// below its release, then identifiers left to right (numeric < alphanumeric).
function compareSemver(a: string, b: string): number {
  const [aCore, aPre] = a.split(/-(.*)/s);
  const [bCore, bPre] = b.split(/-(.*)/s);
  const ac = aCore.split(".").map(Number);
  const bc = bCore.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (ac[i] !== bc[i]) return ac[i] - bc[i];
  if (!aPre || !bPre) return aPre ? -1 : bPre ? 1 : 0;
  const ai = aPre.split(".");
  const bi = bPre.split(".");
  for (let i = 0; i < Math.max(ai.length, bi.length); i++) {
    if (ai[i] === undefined) return -1;
    if (bi[i] === undefined) return 1;
    const an = /^\d+$/.test(ai[i]);
    const bn = /^\d+$/.test(bi[i]);
    if (an && bn && ai[i] !== bi[i]) return Number(ai[i]) - Number(bi[i]);
    if (an !== bn) return an ? -1 : 1;
    if (ai[i] !== bi[i]) return ai[i] < bi[i] ? -1 : 1;
  }
  return 0;
}

describe("main-build chart version", () => {
  it("all charts share one version, which scripts/release.sh sets", () => {
    const versions = charts.map(chartVersion);
    assert.deepEqual(versions, versions.map(() => versions[0]), `chart versions differ: ${versions}`);
  });

  for (const released of ["0.1.0", "0.9.12", "1.0.0-rc.1", "2.3.4"]) {
    it(`first main build after ${released} outranks it`, () => {
      const build = `${mainBase(released)}-main.1792369039.74b4a748`;
      assert.ok(compareSemver(build, released) > 0, `${build} sorts below ${released}`);
    });
  }

  it("later builds outrank earlier ones", () => {
    const base = mainBase(chartVersion("ocidex"));
    assert.ok(compareSemver(`${base}-main.1792369040.00000000`, `${base}-main.1792369039.ffffffff`) > 0);
  });

  it("the current chart version yields the next patch", () => {
    assert.equal(mainBase("0.1.0"), "0.1.1");
    assert.equal(mainBase("1.0.0-rc.1"), "1.0.1");
  });
});
