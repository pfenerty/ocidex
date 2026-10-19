// Collect the license texts of the production npm packages bundled into dist/, for shipping in
// the web image at /licenses (ocidex-9rqq). The Go images get theirs from
// scripts/third-party-licenses.sh.
//
// Usage: node scripts/third-party-licenses.mjs <outdir>   (from web/, after npm ci)
//
// Each package lands in <outdir>/<name>@<version>/ with the license, copying and notice files
// from its root. A production package with none fails the build. OCIDex's own LICENSE is
// copied in by docker/web/Dockerfile, since web/ is the build context's only source here.
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const out = process.argv[2];
if (!out) {
  console.error("usage: third-party-licenses.mjs <outdir>");
  process.exit(1);
}

const licenseFile = /^(licen[cs]e|copying|notice|unlicense)/i;
const pkgs = JSON.parse(execFileSync("npm", ["query", ".prod"], { encoding: "utf8" }));
const missing = [];

mkdirSync(out, { recursive: true });

for (const pkg of pkgs) {
  if (!pkg.path || path.resolve(pkg.path) === process.cwd()) continue;
  const files = readdirSync(pkg.path).filter(
    (f) => licenseFile.test(f) && statSync(path.join(pkg.path, f)).isFile(),
  );
  if (files.length === 0) {
    missing.push(`${pkg.name}@${pkg.version}`);
    continue;
  }
  const dest = path.join(out, `${pkg.name}@${pkg.version}`);
  mkdirSync(dest, { recursive: true });
  for (const f of files) copyFileSync(path.join(pkg.path, f), path.join(dest, f));
}

if (missing.length > 0) {
  console.error(`third-party-licenses: no license file at the root of ${missing.join(", ")}`);
  process.exit(1);
}

writeFileSync(
  path.join(out, "README"),
  "Third-party licenses for the OCIDex web UI in this image.\n\n" +
    "Each directory is an npm package bundled into the UI, named <package>@<version>,\n" +
    "holding the license files from that package's source.\n",
);
