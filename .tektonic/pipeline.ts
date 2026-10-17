import { TektonicProject } from "@tektonic-ci/core";

import { goCacheWs, nodeCacheWs, buildkitCacheWs, buildkitReleaseCacheWs } from "./shared";
import { pushPipeline, prPipeline, tagPipeline, synthDefaults } from "./pipelines";

// ─── Synthesize ─────────────────────────────────────────────────────────────
new TektonicProject({
  name: "ocidex",
  namespace: "ocidex-ci",
  pipelines: [pushPipeline, prPipeline, tagPipeline],
  outdir: "../.tekton",
  repoRelativePath: ".tekton",
  serviceAccountName: "default",
  ...synthDefaults,
  workspaceStorageSize: "5Gi",
  workspaceStorageClass: "local-path",
  defaultPodSecurityContext: {
    runAsUser: 1024,
    runAsGroup: 1024,
    fsGroup: 1024,
  },
  // PAC_EVENT_TYPE / PAC_TARGET_BRANCH (and the rest of PAC_EVENT_ENV) in every step, so the
  // secrets scan and semgrep can scope themselves: a PR scans only its new commits vs the
  // base branch, a push to main scans full history (pacBaseline in script-lib.ts).
  pacEventContext: true,
  // HOME is set pod-wide here (not via stepTemplate.env like goEnv/nodeEnv) because
  // defaultPodSecurityContext's runAsUser: 1024 also applies to Tekton's own injected
  // containers (e.g. creds-init, which materializes the ghcr-docker-config secret into
  // $HOME/.docker/config.json). uid 1024 has no /etc/passwd entry, so without this,
  // $HOME defaults to "/" and creds-init fails with "mkdir /.docker: permission denied".
  // /tekton/home is writable by any uid regardless of HOME/passwd state.
  podTemplateEnv: [{ name: "HOME", value: "/tekton/home" }],
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
    // buildkitd roots for the two image-build chains. 25Gi because
    // --oci-worker-snapshotter=native copies rather than overlays, so every derived stage
    // is a full copy of builder-base; buildkitd.toml caps the working set well below this
    // with a keepBytes GC policy, so the claim size is headroom, not the expected usage.
    // The PVCs themselves live in homelab (talos-cluster/flux/apps/ocidex-ci/cache-pvcs.yaml)
    // — tektonic emits the `claimName: ocidex-<workspace-name>` reference, not the claim.
    {
      workspace: buildkitCacheWs,
      storageSize: "25Gi",
      storageClassName: "local-path",
    },
    {
      workspace: buildkitReleaseCacheWs,
      storageSize: "25Gi",
      storageClassName: "local-path",
    },
  ],
});
