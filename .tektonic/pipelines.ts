// The three pipelines, importable without synthesizing: pipeline.ts (the tektonic entry)
// builds the project from them, and test/ asserts on them in memory.
import { GitPipeline, TRIGGER_EVENTS, gated, serial, DEFAULT_BASE_IMAGE } from "@tektonic-ci/core";

import { sourceWs } from "./shared";
import {
  goChanged,
  nodeChanged,
  sourceChanged,
  pipelineChanged,
  chartsChanged,
  codegenChanged,
} from "./changes";
import { goFmt } from "./jobs/go-fmt/spec";
import { goBuild } from "./jobs/go-build/spec";
import { goTest } from "./jobs/go-test/spec";
import { goIntegration } from "./jobs/go-integration/spec";
import { frontendLint } from "./jobs/frontend-lint/spec";
import { goLint } from "./jobs/go-lint/spec";
import { codegenCheck } from "./jobs/codegen-check/spec";
import { openapiCheck } from "./jobs/openapi-check/spec";
import { openapiBreaking } from "./jobs/openapi-breaking/spec";
import { goVulncheck } from "./jobs/go-vulncheck/spec";
import { webSecurity } from "./jobs/web-security/spec";
import { secretsScan } from "./jobs/secrets-scan/spec";
import { semgrep } from "./jobs/semgrep/spec";
import { imageBuilds, imageBuildsTag } from "./jobs/image-build/spec";
import { helmPublish } from "./jobs/helm-publish/spec";
import { helmRelease } from "./jobs/helm-release/spec";
import { ghRelease } from "./jobs/gh-release/spec";
import { tektonCheck } from "./jobs/tekton-check/spec";
import { helmCheck } from "./jobs/helm-check/spec";
import { sbomPush } from "./jobs/sbom-push/spec";

// ─── Task groups ──────────────────────────────────────────────────────────────
// Core build/verify tasks + the always-on security scans. Run ungated on push so
// the publish path (main) always rebuilds and re-scans.
const coreTasks = [goFmt, goLint, goTest, goBuild, openapiCheck, codegenCheck, frontendLint, goIntegration];
// go-vulncheck = reachability-aware Go gate (replaced grype-on-Go, which only added
// noise for Go — e.g. flagging the unreachable, unfixable x/crypto/openpgp advisory);
// web-security = frontend npm deps (grype — govulncheck can't scan npm); semgrep = SAST;
// secrets-scan = gitleaks.
const securityTasks = [goVulncheck, webSecurity, secretsScan, semgrep];

// ─── Synthesis defaults ──────────────────────────────────────────────────────
// Project options that change what a task synthesizes to, shared by the project in
// pipeline.ts and the in-memory synthesis in test/ so both see the same output.
export const synthDefaults = {
  // tektonic 2.x defaults injected steps (status reporter, git clone) to a neutral
  // sh+git image; ours are nushell, so keep the apko-cicd base image they ran on under 1.x.
  injectedStepImage: DEFAULT_BASE_IMAGE,
  // Every image this pipeline runs is referenced by a mutable tag: base:stable and
  // moby/buildkit:rootless are moving by design, and the version-pinned apko-cicd images
  // (golang:1.26, syft:1.45.1, …) are republished under the same tag on every rebuild.
  // The kubelet defaults to IfNotPresent for any tag but :latest, so a node that pulled
  // once serves those layers forever with no signal — that is what produced ocidex-qzz2.
  // Lands in each task's stepTemplate, so it covers the injected cache and reporter steps
  // too, and tektonic stamps it onto sidecars, which Tekton's stepTemplate never reaches.
  //
  // Digest-pinning the refs instead is the alternative ADR-038 rejected: Renovate cannot
  // run `make tekton-synth`, so every bump would land a PR that tekton-check fails until
  // a human re-synths.
  defaultImagePullPolicy: "Always" as const,
};

// ─── Pipelines ────────────────────────────────────────────────────────────────
export const pushPipeline = new GitPipeline({
  name: "ocidex-push",
  workspace: sourceWs,
  // Publish only from main — feature-branch pushes shouldn't run image builds.
  // Cancel an older in-progress run for the same branch when a newer one starts,
  // so two serial image-build chains never overlap and burst the single node's
  // memory (risking a node-wide OOM instead of a per-container one).
  trigger: { rules: [{ on: TRIGGER_EVENTS.PUSH, branch: "main" }], cancelInProgress: true },
  // All three pipelines share one generated git-clone task, so clone depth must be
  // consistent: the PR pipeline's onChanges needs full history for a reachable
  // merge-base. The repo is tiny (~150 commits), so full clone is negligible.
  cloneDepth: "full",
  // The image builds run serially (chained so two builds never overlap and burst the
  // single node's memory), so the timeout tracks 10 × per-build time. This was 4h when
  // each build took ~12-16 min; ocidex-2vr cut that with a persistent buildkitd root,
  // and run push-t2t4l came in at 70 min end to end (61 min of image builds).
  //
  // 2h30m, not 2h: the number that has to fit is not the 70 min warm run but a COLD
  // one — first run after the cache PVC is recreated or rebinds to another node. Cold
  // builds measured ~11 min single-arch, so 10 × that plus the web (~14 min) and
  // operator (~9 min) outliers plus ~8 min of pre-build tasks lands close to 2h, and a
  // 2h ceiling would turn a cache miss into a pipeline failure. Revisit if the builds
  // are ever parallelised, or if ocidex-2j2 lands and cuts the per-binary compile.
  //
  // 3h since ocidex-113l: go-integration-test (25m budget) now sits between go-build and
  // the image chain, and its sidecar-backed suite is not something the cold-run estimate
  // above accounted for.
  timeout: "3h",
  tasks: [...coreTasks, ...securityTasks, ...serial(imageBuilds), helmCheck, helmPublish, sbomPush],
});

// PR pipeline: gate the expensive Go jobs on whether the branch touched Go/Docker/db
// paths vs main (classic `when` guards — no CEL feature flag needed). `cloneDepth:
// 'full'` gives onChanges a reachable merge-base; otherwise it fails open and nothing
// is skipped. Secrets + Semgrep run unconditionally (cheap / multi-language). No image
// builds run on PRs, so nothing to gate there.
//
// Depended-upon tasks are gated too: a frontend-only PR skips every Go task, go-build
// included, and a Go-only PR skips frontend-lint. Tekton still runs a skipped task's
// dependents, so the remaining `needs` are only ordering (cache warmth), never artifacts:
// openapi-check and codegen-check restore their own caches when go-build or frontend-lint
// did not run. Each condition's detect-* task is wired in by tektonic.
export const prPipeline = new GitPipeline({
  name: "ocidex-pull-request",
  workspace: sourceWs,
  trigger: { rules: [{ on: TRIGGER_EVENTS.PULL_REQUEST }], cancelInProgress: true },
  cloneDepth: "full",
  tasks: [
    gated(goBuild, { when: goChanged }),
    gated(frontendLint, { when: nodeChanged }),
    gated(goFmt, { when: goChanged }),
    gated(goLint, { when: goChanged }),
    gated(goTest, { when: goChanged }),
    gated(goIntegration, { when: goChanged }),
    gated(openapiCheck, { when: goChanged }),
    gated(codegenCheck, { when: codegenChanged }),
    gated(openapiBreaking, { when: goChanged }),
    gated(goVulncheck, { when: goChanged }),
    // web-security is a leaf → gate on the frontend bucket. semgrep is multi-language SAST →
    // run when Go OR frontend code changed (skips docs/CI-only PRs). secrets-scan stays
    // ungated: secrets can land in any file, and it's cheap.
    gated(webSecurity, { when: nodeChanged }),
    gated(semgrep, { when: sourceChanged }),
    secretsScan,
    // Fails if .tekton drifts from .tektonic/ or synth breaks — only when pipeline defs change.
    gated(tektonCheck, { when: pipelineChanged }),
    // Helm lint + PodSecurity render check — only when the charts, the policies, or the
    // driver script changed. Leaf task on this pipeline (nothing publishes on a PR), so
    // gating it is safe; on push/tag it runs ungated as a `needs` of helm-publish/-release.
    gated(helmCheck, { when: chartsChanged }),
  ],
});

export const tagPipeline = new GitPipeline({
  name: "ocidex-tag",
  workspace: sourceWs,
  // Server releases only. The Go SDK is tagged pkg/client/vX.Y.Z (ADR-052); the Go proxy
  // serves it straight from the tag, and it must not set off an image and chart release.
  // A TAG rule's `branch` filters the tag name (@tektonic-ci/core 2.3.0+), so "v*" emits
  // on-target-branch [refs/tags/v*] and pkg/client/v* tags never match.
  trigger: {
    rules: [{ on: TRIGGER_EVENTS.TAG, branch: "v*" }],
    cancelInProgress: true,
  },
  cloneDepth: "full",
  // Same serial image-build chain as the push pipeline, plus helm-release and
  // gh-release. Deliberately still 4h while push is 2h30m: these builds are multi-arch
  // (linux/amd64,linux/arm64), roughly double the work per image, and no tag pipeline
  // has yet run since ocidex-2vr — buildkit-release-cache is a separate, still-cold
  // PVC. Lower this only once a real tag run has been measured.
  timeout: "4h",
  // sbomPush pulls goBuild in via `needs` (it must not race another Go task's cache
  // restore). That extra compile is the price of cataloguing the tagged binaries.
  tasks: [...serial(imageBuildsTag), helmCheck, helmRelease, ghRelease, sbomPush],
});
