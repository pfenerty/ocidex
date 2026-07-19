import { GitPipeline, TektonicProject, TRIGGER_EVENTS, gated } from "@pfenerty/tektonic";

import { goCacheWs, nodeCacheWs } from "./shared";
import { goChanged, detectTasks } from "./changes";
import { goFmt } from "./jobs/go-fmt/spec";
import { goBuild } from "./jobs/go-build/spec";
import { goTest } from "./jobs/go-test/spec";
import { frontendLint } from "./jobs/frontend-lint/spec";
import { openapiCheck } from "./jobs/openapi-check/spec";
import { goSecurity } from "./jobs/go-security/spec";
import { secretsScan } from "./jobs/secrets-scan/spec";
import { semgrep } from "./jobs/semgrep/spec";
import { imageBuilds, imageBuildsTag } from "./jobs/image-build/spec";
import { helmPublish } from "./jobs/helm-publish/spec";
import { helmRelease } from "./jobs/helm-release/spec";
import { ghRelease } from "./jobs/gh-release/spec";

// ─── Task groups ──────────────────────────────────────────────────────────────
// Core build/verify tasks + the always-on security scans. Run ungated on push so
// the publish path (main) always rebuilds and re-scans.
const coreTasks = [goFmt, goTest, goBuild, openapiCheck, frontendLint];
const securityTasks = [goSecurity, secretsScan, semgrep];

// ─── Pipelines ────────────────────────────────────────────────────────────────
const pushPipeline = new GitPipeline({
  name: "ocidex-push",
  // Publish only from main — feature-branch pushes shouldn't run image builds.
  // Cancel an older in-progress run for the same branch when a newer one starts,
  // so two serial image-build chains never overlap and burst the single node's
  // memory (risking a node-wide OOM instead of a per-container one).
  trigger: { rules: [{ on: TRIGGER_EVENTS.PUSH, branch: "main" }], cancelInProgress: true },
  // All three pipelines share one generated git-clone task, so clone depth must be
  // consistent: the PR pipeline's onChanges needs full history for a reachable
  // merge-base. The repo is tiny (~150 commits), so full clone is negligible.
  cloneDepth: "full",
  // Multi-arch image builds + helm exceed Tekton's 1h default on the homelab node.
  timeout: "2h",
  tasks: [...coreTasks, ...securityTasks, ...imageBuilds, helmPublish],
});

// PR pipeline: gate the expensive Go jobs on whether the branch touched Go/Docker/db
// paths vs main (classic `when` guards — no CEL feature flag needed). `cloneDepth:
// 'full'` gives onChanges a reachable merge-base; otherwise it fails open and nothing
// is skipped. Secrets + Semgrep run unconditionally (cheap / multi-language). No image
// builds run on PRs, so nothing to gate there.
//
// Only leaf tasks are gated: `goBuild` and `frontendLint` are dependencies (of
// go-test / openapi-check), so they are pulled into the graph ungated via `needs`
// and run on every PR. Gating a depended-upon task collides with the raw reference
// its dependents hold. Net effect: a frontend-only PR skips go-fmt/test/openapi-check
// /go-security (the heavy Go work); go-build + frontend-lint still run.
const prPipeline = new GitPipeline({
  name: "ocidex-pull-request",
  trigger: { rules: [{ on: TRIGGER_EVENTS.PULL_REQUEST }], cancelInProgress: true },
  cloneDepth: "full",
  tasks: [
    ...detectTasks,
    gated(goFmt, { when: goChanged }),
    gated(goTest, { when: goChanged }),
    gated(openapiCheck, { when: goChanged }),
    gated(goSecurity, { when: goChanged }),
    secretsScan,
    semgrep,
  ],
});

const tagPipeline = new GitPipeline({
  name: "ocidex-tag",
  trigger: { rules: [{ on: TRIGGER_EVENTS.TAG, branch: "refs/tags/*" }], cancelInProgress: true },
  cloneDepth: "full",
  timeout: "2h",
  tasks: [...imageBuildsTag, helmRelease, ghRelease],
});

// ─── Synthesize ─────────────────────────────────────────────────────────────
new TektonicProject({
  name: "ocidex",
  namespace: "ocidex-ci",
  pipelines: [pushPipeline, prPipeline, tagPipeline],
  outdir: "../.tekton",
  repoRelativePath: ".tekton",
  serviceAccountName: "default",
  workspaceStorageSize: "5Gi",
  workspaceStorageClass: "local-path",
  defaultPodSecurityContext: {
    runAsUser: 1024,
    runAsGroup: 1024,
    fsGroup: 1024,
  },
  caches: [
    {
      workspace: goCacheWs,
      storageSize: "5Gi",
      storageClassName: "local-path",
    },
    {
      workspace: nodeCacheWs,
      storageSize: "2Gi",
      storageClassName: "local-path",
    },
  ],
});
