import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { describe, it } from "node:test";

// Every buildctl-daemonless.sh step waits ~43s for buildkitd, not the script's ~2.2s
// default (ocidex-ktoh). Read off the generated tasks, so a new image task that skips
// imageBuildTask's env is caught.

const tasksDir = path.join(__dirname, "..", "..", ".tekton", "tasks");
const imageTasks = readdirSync(tasksDir).filter((f) => /^image-(build|release)-.*\.k8s\.yaml$/.test(f));

describe("buildkitd connect budget", () => {
  it("finds the image tasks", () => {
    assert.ok(imageTasks.length >= 20, `only ${imageTasks.length} image tasks found`);
  });

  for (const file of imageTasks) {
    it(`${file} sets BUILDCTL_CONNECT_RETRIES_MAX=60`, () => {
      const yaml = readFileSync(path.join(tasksDir, file), "utf8");
      assert.match(yaml, /- name: BUILDCTL_CONNECT_RETRIES_MAX\n\s+value: "60"/);
    });
  }
});
