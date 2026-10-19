import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { describe, it } from "node:test";

// Every shipped image carries its third-party license texts at /licenses (ocidex-9rqq).

const repoRoot = path.join(__dirname, "..", "..");
const read = (p: string) => readFileSync(path.join(repoRoot, p), "utf8");

// Dockerfile instructions with `\` continuations joined and comments dropped.
function instructions(dockerfile: string): string[] {
  return dockerfile
    .replace(/\\\n/g, " ")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
}

// Stages that end in an ENTRYPOINT, i.e. the ones shipped as images.
function shippedStages(dockerfile: string): Map<string, string[]> {
  const stages = new Map<string, string[]>();
  let current: string[] = [];
  let name = "";
  for (const ins of instructions(dockerfile)) {
    if (ins.startsWith("FROM ")) {
      current = [];
      name = / AS (\S+)$/i.exec(ins)?.[1] ?? "(final)";
    }
    current.push(ins);
    if (ins.startsWith("ENTRYPOINT ") || ins.startsWith("EXPOSE ")) stages.set(name, current);
  }
  return stages;
}

const cmdPackages = (ins: string) => (ins.match(/\.\/cmd\/[\w-]+/g) ?? []).sort();

describe("image license texts", () => {
  const goDockerfile = read("docker/Dockerfile");

  for (const [stage, ins] of shippedStages(goDockerfile)) {
    it(`docker/Dockerfile ${stage} ships /licenses`, () => {
      assert.ok(ins.includes("COPY --from=build-all /app/licenses /licenses"), `${stage} has no /licenses`);
    });
  }

  it("docker/Dockerfile collects licenses for exactly the binaries it builds", () => {
    const all = instructions(goDockerfile);
    const build = all.find((i) => i.includes("go build -ldflags"));
    const licenses = all.find((i) => i.includes("go-licenses report"));
    assert.ok(build && licenses, "go build or go-licenses report step not found");
    assert.deepEqual(cmdPackages(licenses), cmdPackages(build));
  });

  it("docker/web/Dockerfile ships /licenses", () => {
    const final = [...shippedStages(read("docker/web/Dockerfile")).values()].at(-1) ?? [];
    assert.ok(final.includes("COPY --from=build /app/dist/third-party-licenses.txt /licenses/THIRD_PARTY_NOTICES"));
    assert.ok(final.includes("COPY LICENSE /licenses/LICENSE"));
    assert.match(read("web/vite.config.ts"), /dist\/third-party-licenses\.txt/);
  });
});
