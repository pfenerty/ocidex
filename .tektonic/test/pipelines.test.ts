import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { synthPipeline, synthTasks } from "@tektonic-ci/core/testing";
import type { PipelineView } from "@tektonic-ci/core/testing";

import { prPipeline, pushPipeline, synthDefaults } from "../pipelines";
import { changePaths } from "../changes";
import { CHECK_TIP_TASK } from "../supersede";

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
const tipRef = `$(tasks.${CHECK_TIP_TASK}.results.tip)`;

function isTipClause(clause: { input: unknown; operator: string; values: unknown }): boolean {
  return String(clause.input) === tipRef && clause.operator === "in" && JSON.stringify(clause.values) === '["true"]';
}

// Which of the PR pipeline's tasks would run for this changed-file set, on a run that is
// still its branch's tip. Every gate this pipeline uses is a classic `in ["true"]` guard on
// a detect-* result or on check-tip; anything else fails the test rather than being guessed at.
function runsFor(pr: PipelineView, files: string[]): Set<string> {
  const running = new Set<string>();
  for (const name of pr.taskNames) {
    const runs = pr.when(name).every((clause) => {
      if (isTipClause(clause)) return true;
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
// Tasks the PR pipeline deliberately runs on every change (gitleaks only gated on isTip).
const alwaysRun = ["git-clone", "gitleaks-secrets"];

describe("PR pipeline gating", () => {
  it("records paths for every detect task it emits", () => {
    const detects = pr.taskNames.filter((n) => n.startsWith("detect-"));
    assert.ok(detects.length > 0);
    for (const d of detects) assert.ok(changePaths[d], d);
  });

  it("gates every task on a file change except the always-run set", () => {
    const unconditional = pr.taskNames.filter(
      (n) =>
        !n.startsWith("detect-") &&
        !n.startsWith("set-status-") &&
        n !== CHECK_TIP_TASK &&
        !pr.when(n).some((c) => !isTipClause(c)),
    );
    assert.deepEqual(unconditional.sort(), [...alwaysRun].sort());
  });

  it("skips every task but the clone and check-tip itself on a superseded run", () => {
    const work = pr.taskNames.filter(
      (n) => !n.startsWith("detect-") && !n.startsWith("set-status-") && n !== CHECK_TIP_TASK && n !== "git-clone",
    );
    for (const n of work) assert.ok(pr.when(n).some(isTipClause), n);
  });

  it("skips every Go task on a frontend-only change", () => {
    const runs = runsFor(pr, ["web/src/App.tsx", "web/package-lock.json"]);
    for (const t of goTasks) assert.equal(runs.has(t), false, t);
    for (const t of [...frontendTasks, "semgrep-sast"]) assert.equal(runs.has(t), true, t);
  });

  it("skips the frontend tasks on a Go-only change", () => {
    const runs = runsFor(pr, ["internal/api/server.go"]);
    for (const t of frontendTasks) assert.equal(runs.has(t), false, t);
    for (const t of [...goTasks, "semgrep-sast"]) assert.equal(runs.has(t), true, t);
  });

  it("runs only the always-run set on a docs-only change", () => {
    const runs = runsFor(pr, ["docs/ARCHITECTURE.md"]);
    const work = [...runs].filter((n) => !n.startsWith("detect-") && !n.startsWith("set-status-") && n !== CHECK_TIP_TASK);
    assert.deepEqual(work.sort(), [...alwaysRun].sort());
  });

  it("runs codegen-check alone when only a generated file changes", () => {
    const runs = runsFor(pr, ["docs/AUTH_MATRIX.md"]);
    assert.equal(runs.has("codegen-check"), true);
    assert.equal(runs.has("go-build"), false);
  });

  it("runs docs-build alone on a site-only change", () => {
    const runs = runsFor(pr, ["site/src/content/docs/index.mdx"]);
    const work = [...runs].filter((n) => !n.startsWith("detect-") && !n.startsWith("set-status-") && n !== CHECK_TIP_TASK);
    assert.deepEqual(work.sort(), [...alwaysRun, "docs-build"].sort());
  });

  it("runs docs-build when a generated reference page's source changes", () => {
    for (const f of ["internal/config/config.go", "web/openapi.json", "charts/ocidex/values.yaml"]) {
      assert.equal(runsFor(pr, [f]).has("docs-build"), true, f);
    }
  });

  it("runs the integration suite when its sidecar images change", () => {
    assert.equal(runsFor(pr, [".tektonic/jobs/go-integration/spec.ts"]).has("go-integration-test"), true);
  });

  it("orders go-integration-test after go-test", () => {
    assert.ok(pr.runAfter("go-integration-test").includes("go-test"));
  });
});

// ─── Push: superseded runs ───────────────────────────────────────────────────
// Push runs queue under the PAC concurrency_limit, which disables cancel-in-progress. Every
// push task must be gated on check-tip, so a queued run for an old commit skips its image
// builds instead of racing the newest commit's run for the shared buildkitd root.
describe("push pipeline superseded-run guard", () => {
  const push = synthPipeline(pushPipeline, synthDefaults);

  it("gates every task on check-tip", () => {
    const work = push.taskNames.filter(
      (n) => n !== CHECK_TIP_TASK && n !== "git-clone" && !n.startsWith("set-status-"),
    );
    assert.ok(work.includes("image-build-api"));
    for (const n of work) assert.ok(push.when(n).some(isTipClause), n);
  });

  it("keeps the image builds serial", () => {
    assert.ok(push.runAfter("image-build-scanner-worker").includes("image-build-api"));
  });
});

// ─── Report-only tasks ───────────────────────────────────────────────────────
// A report-only scan posts a red GitHub check for findings but must never fail the
// PipelineRun: its own steps continue on error, and its report-status step does not
// re-raise the worst exit code the way a gating task's does.
const reportOnly = ["govulncheck-scan", "semgrep-sast", "gitleaks-secrets", "grype-vuln-web"];
// Injected by tektonic around the user steps; not part of the scan's own verdict.
const injected = /^(restore|save)-.*-cache$|^report-status$/;
const reraise = /^exit \$exit_code$/m;

for (const [label, pipeline] of [
  ["push", pushPipeline],
  ["pull-request", prPipeline],
] as const) {
  describe(`report-only tasks on ${label}`, () => {
    const tasks = synthTasks(pipeline, synthDefaults);

    for (const name of reportOnly) {
      it(`${name} never fails the run`, () => {
        const task = tasks[name];
        assert.ok(task, `${name} is not in this pipeline`);
        for (const step of task.stepNames.filter((s) => !injected.test(s))) {
          assert.equal(task.step(step).onError, "continue", `${name}/${step}`);
        }
        assert.doesNotMatch(task.script("report-status"), reraise);
      });
    }

    it("a gating task does re-raise", () => {
      assert.match(tasks["go-test"].script("report-status"), reraise);
    });
  });
}
