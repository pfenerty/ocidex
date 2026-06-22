import { GitPipeline, PACProject, TRIGGER_EVENTS } from "@pfenerty/tektonic";

import { goCacheWs, nodeCacheWs } from "./shared";
import { goFmt } from "./jobs/go-fmt/spec";
import { goBuild } from "./jobs/go-build/spec";
import { goTest } from "./jobs/go-test/spec";
import { frontendLint } from "./jobs/frontend-lint/spec";
import { openapiCheck } from "./jobs/openapi-check/spec";
import { imageBuilds, imageBuildsTag } from "./jobs/image-build/spec";
import { helmPublish } from "./jobs/helm-publish/spec";
import { helmRelease } from "./jobs/helm-release/spec";
import { ghRelease } from "./jobs/gh-release/spec";

// ─── Pipelines ──────────────────────────────────────────────────────────────
const allTasks = [goFmt, goTest, goBuild, openapiCheck, frontendLint];

const pushPipeline = new GitPipeline({
  name: "ocidex-push",
  triggers: [TRIGGER_EVENTS.PUSH],
  tasks: [...allTasks, ...imageBuilds, helmPublish],
});

const prPipeline = new GitPipeline({
  name: "ocidex-pull-request",
  triggers: [TRIGGER_EVENTS.PULL_REQUEST],
  tasks: allTasks,
});

const tagPipeline = new GitPipeline({
  name: "ocidex-tag",
  triggers: [TRIGGER_EVENTS.TAG],
  tasks: [...imageBuildsTag, helmRelease, ghRelease],
});

// ─── Synthesize ─────────────────────────────────────────────────────────────
new PACProject({
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
