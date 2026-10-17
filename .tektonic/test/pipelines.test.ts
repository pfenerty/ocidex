import { describe, expect, it } from "vitest";
import { synthPipeline, synthTasks } from "@tektonic-ci/core/testing";
import type { PipelineView } from "@tektonic-ci/core/testing";

import { prPipeline, pushPipeline, synthDefaults } from "../pipelines";
import { changePaths } from "../changes";

// ─── PR gating ────────────────────────────────────────────────────────────────
// Evaluates the PR pipeline's `when` gates against a changed-file set, the way each
// detect-* task's `git diff --name-only main...HEAD -- <pathspecs>` would.

// Git `:(glob)` pathspec semantics: `**` spans directories, `*` and `?` do not, and a
// leading `**/` also matches at the root.
function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (glob.startsWith("**/", i)) {
      re += "(?:.*/)?";
      i += 2;
    } else if (glob.startsWith("**", i)) {
      re += ".*";
      i += 1;
    } else if (c === "*") {
      re += "[^/]*";
    } else if (c === "?") {
      re += "[^/]";
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${re}$`);
}

function bucketMatches(detectTask: string, files: string[]): boolean {
  const paths = changePaths[detectTask];
  if (!paths) throw new Error(`no paths recorded for ${detectTask}`);
  const res = paths.map(globToRegExp);
  return files.some((f) => res.some((re) => re.test(f)));
}

const resultRef = /^\$\(tasks\.([\w-]+)\.results\.changed\)$/;

// Which of the PR pipeline's tasks would run for this changed-file set. Every gate this
// pipeline uses is a classic `in ["true"]` guard on a detect-* result; anything else fails
// the test rather than being guessed at.
function runsFor(pr: PipelineView, files: string[]): Set<string> {
  const running = new Set<string>();
  for (const name of pr.taskNames) {
    const runs = pr.when(name).every((clause) => {
      const m = resultRef.exec(String(clause.input));
      if (!m || clause.operator !== "in" || JSON.stringify(clause.values) !== '["true"]') {
        throw new Error(`${name}: unexpected when clause ${JSON.stringify(clause)}`);
      }
      return bucketMatches(m[1], files);
    });
    if (runs) running.add(name);
  }
  return running;
}

const pr = synthPipeline(prPipeline, synthDefaults);

const goTasks = [
  "go-build",
  "gofmt-check",
  "go-lint",
  "go-test",
  "go-integration-test",
  "openapi-verify",
  "openapi-breaking",
  "govulncheck-scan",
  "codegen-check",
];
const frontendTasks = ["eslint-lint-web", "grype-vuln-web"];
// Tasks the PR pipeline deliberately runs on every change.
const alwaysRun = ["git-clone", "gitleaks-secrets"];

describe("PR pipeline gating", () => {
  it("records paths for every detect task it emits", () => {
    const detects = pr.taskNames.filter((n) => n.startsWith("detect-"));
    expect(detects.length).toBeGreaterThan(0);
    for (const d of detects) expect(changePaths[d], d).toBeDefined();
  });

  it("gates every task except the always-run set", () => {
    const ungated = pr.taskNames.filter(
      (n) => !pr.isGated(n) && !n.startsWith("detect-") && !n.startsWith("set-status-"),
    );
    expect(ungated.sort()).toEqual([...alwaysRun].sort());
  });

  it("skips every Go task on a frontend-only change", () => {
    const runs = runsFor(pr, ["web/src/App.tsx", "web/package-lock.json"]);
    for (const t of goTasks) expect(runs.has(t), t).toBe(false);
    for (const t of [...frontendTasks, "semgrep-sast"]) expect(runs.has(t), t).toBe(true);
  });

  it("skips the frontend tasks on a Go-only change", () => {
    const runs = runsFor(pr, ["internal/api/server.go"]);
    for (const t of frontendTasks) expect(runs.has(t), t).toBe(false);
    for (const t of [...goTasks, "semgrep-sast"]) expect(runs.has(t), t).toBe(true);
  });

  it("runs only the always-run set on a docs-only change", () => {
    const runs = runsFor(pr, ["docs/ARCHITECTURE.md"]);
    const work = [...runs].filter((n) => !n.startsWith("detect-") && !n.startsWith("set-status-"));
    expect(work.sort()).toEqual([...alwaysRun].sort());
  });

  it("runs codegen-check alone when only a generated file changes", () => {
    const runs = runsFor(pr, ["docs/AUTH_MATRIX.md"]);
    expect(runs.has("codegen-check")).toBe(true);
    expect(runs.has("go-build")).toBe(false);
  });

  it("orders go-integration-test after go-test", () => {
    expect(pr.runAfter("go-integration-test")).toContain("go-test");
  });
});

// ─── Report-only tasks ───────────────────────────────────────────────────────
// A report-only scan posts a red GitHub check for findings but must never fail the
// PipelineRun: its own steps continue on error, and its report-status step does not
// re-raise the worst exit code the way a gating task's does.
const reportOnly = ["govulncheck-scan", "semgrep-sast", "gitleaks-secrets", "grype-vuln-web"];
// Injected by tektonic around the user steps; not part of the scan's own verdict.
const injected = /^(restore|save)-.*-cache$|^report-status$/;

describe.each([
  ["push", pushPipeline],
  ["pull-request", prPipeline],
])("report-only tasks on %s", (_label, pipeline) => {
  const tasks = synthTasks(pipeline, synthDefaults);

  it.each(reportOnly)("%s never fails the run", (name) => {
    const task = tasks[name];
    expect(task, `${name} is not in this pipeline`).toBeDefined();
    for (const step of task.stepNames.filter((s) => !injected.test(s))) {
      expect(task.step(step).onError, `${name}/${step}`).toBe("continue");
    }
    expect(task.script("report-status")).not.toMatch(/^exit \$exit_code$/m);
  });

  it("a gating task does re-raise", () => {
    expect(tasks["go-test"].script("report-status")).toMatch(/^exit \$exit_code$/m);
  });
});
