import * as path from "path";
import { ChainsImage, Task, Workspace, ScriptInput, scriptFromFile, nu } from "@pfenerty/tektonic";
import {
  statusReporter,
  dockerConfigVolume,
  baseImage,
  buildkitCacheWs,
  buildkitReleaseCacheWs,
} from "../../shared";
import { goTest } from "../go-test/spec";
import { goIntegration } from "../go-integration/spec";
import { openapiCheck } from "../openapi-check/spec";

type EnvVar = { name: string; value: string };

// buildkitd GC policy for the persistent root. Declaring an explicit gcpolicy REPLACES
// buildkit's built-in defaults, so this single `all = true` rule governs the whole store:
// keep up to 14GiB, prune oldest beyond that. An explicit ceiling is mandatory here —
// --oci-worker-snapshotter=native copies rather than overlays, so every derived stage is a
// full copy of builder-base and an ungoverned root fills the 25Gi claim quickly.
const buildkitdToml = `[worker.oci]
  gc = true

[[worker.oci.gcpolicy]]
  keepBytes = 15032385536
  all = true
`;

// build.sh / release.sh are static and identical across images; per-image values
// (dockerfile, image name, optional target) are passed as step env vars.
const buildScript = scriptFromFile(path.join(__dirname, "build.sh"));
const releaseScript = scriptFromFile(path.join(__dirname, "release.sh"));

// Clean build context (ocidex-2vr.1). By the time image-build runs, the shared source
// workspace also holds web/node_modules, .git, and the .go-mod/.go-build caches seeded by
// go-build — measured at 468MB transferred per build, ten times per pipeline, with neither
// .dockerignore taking effect. Rather than debug dockerignore resolution, build from a tree
// materialised straight out of the commit: ~8MB, and byte-identical for a given revision,
// which is the precondition for `COPY . .` in builder-base being a stable cache key.
const ctxDir = ".buildctx";
const ctxTar = ".buildctx.tar";

// Shared Task skeleton. Each image declares a ChainsImage (Tekton Chains build
// subject); build.sh/release.sh write the pushed ref + digest to its result paths.
// `extraNeeds` chains the builds serially (see serialChain).
function buildImageTask(
  taskName: string,
  imageName: string,
  script: ScriptInput,
  imageEnv: EnvVar[],
  cacheWs: Workspace,
  extraNeeds: Task[] = [],
): Task {
  const chains = new ChainsImage({ name: imageName });
  const buildkitRoot = `${cacheWs.path}/root`;
  const buildkitConfig = `${cacheWs.path}/buildkitd.toml`;
  return new Task({
    name: taskName,
    statusReporter,
    // goIntegration gates publication: a failing integration test must skip the whole
    // image chain rather than ship. This also applies to imageBuildsTag — serialChain
    // backs both — so release builds carry the same gate.
    needs: [goTest, goIntegration, openapiCheck, ...extraNeeds],
    workspaces: [cacheWs],
    volumes: [dockerConfigVolume],
    results: [...chains.results],
    steps: [
      // Runs at the pod default uid 1024 (no securityContext override), which is what can
      // write the PVC root: the build step below runs as uid/gid 1000 — buildkit's rootless
      // user — against a volume the kubelet chowned to fsGroup 1024. Making one dedicated
      // subdirectory world-writable is the least invasive fix; overriding the build step's
      // runAsGroup instead risks breaking rootlesskit's subuid/subgid mapping.
      {
        name: "prepare-buildkit-root",
        image: baseImage,
        computeResources: {
          requests: { cpu: "25m", memory: "64Mi" },
          limits: { cpu: "200m", memory: "128Mi" },
        },
        script: nu`
mkdir "${buildkitRoot}"
^chmod 0777 "${buildkitRoot}"
'${buildkitdToml}' | save --force "${buildkitConfig}"
# Size of the carried-over store, for tuning keepBytes against reality. Best-effort:
# a missing du must not fail the build.
try { ^du -sh "${buildkitRoot}" } catch { print "du unavailable" }
`,
      },
      // Materialise the commit tree into .buildctx so buildctl builds from exactly the
      // tracked files and nothing else. Runs at the pod default uid 1024 (the workspace
      // owner); the uid-1000 build step only reads it, and tar's default 0755/0644 modes
      // make that work without a chmod. Guarded on the revision so the nine subsequent
      // builds in the chain reuse the extraction — and, by leaving mtimes untouched, keep
      // buildkit's local-source diff a no-op.
      {
        name: "prepare-build-context",
        image: baseImage,
        workingDir: "$(workspaces.workspace.path)",
        computeResources: {
          requests: { cpu: "25m", memory: "64Mi" },
          limits: { cpu: "500m", memory: "256Mi" },
        },
        script: nu`
let rev = "$(params.revision)"
let stamp = "${ctxDir}/.ctxrev"

if ($stamp | path exists) and (open --raw $stamp | str trim) == $rev {
  log "build context already materialised for this revision"
} else {
  rm --recursive --force "${ctxDir}"
  rm --force "${ctxTar}"
  # Never pipe git archive into tar here: nushell coerces pipeline data to text and
  # corrupts the tar stream. Stage it as a file instead.
  #
  # -c safe.directory: the workspace PVC's contents are not owned by this step's uid, so
  # git's dubious-ownership guard refuses to operate on it. Passing the exemption on the
  # command line keeps it scoped to this one invocation — writing it into a config file
  # would need a writable GIT_CONFIG_GLOBAL that the other Go tasks already point elsewhere.
  ^git -c safe.directory='*' archive --format=tar --output "${ctxTar}" $rev
  mkdir "${ctxDir}"
  ^tar -xf "${ctxTar}" -C "${ctxDir}"
  rm --force "${ctxTar}"
  $rev | save --force $stamp
  log "materialised clean build context"
}
^du -sh "${ctxDir}"
`,
      },
      {
        name: "build-and-push",
        image: "moby/buildkit:rootless",
        securityContext: {
          seccompProfile: { type: "Unconfined" },
          allowPrivilegeEscalation: true,
          runAsUser: 1000,
          runAsGroup: 1000,
          capabilities: { drop: [], add: ["SETUID", "SETGID"] },
        },
        workingDir: "$(workspaces.workspace.path)",
        // Limit measured empirically: a single linux/amd64 build (`api` image) peaked at
        // ~471Mi real memory (kubectl top, 10s sampling) over an ~11min run. 2Gi keeps
        // >50% headroom over that peak while covering heavier, unmeasured image types
        // (e.g. `web`'s frontend bundling step) — tight enough that a genuine burst hits
        // this container's own OOMKilled instead of growing large enough to trip Talos's
        // node-wide OOMController (see ocidex-asx).
        computeResources: {
          requests: { cpu: "500m", memory: "1Gi" },
          limits: { cpu: "4", memory: "2Gi" },
        },
        env: [
          { name: "DOCKER_CONFIG", value: "/tmp/docker-auth" },
          // buildctl-daemonless.sh passes these straight to the buildkitd it starts.
          // --root moves the content store, snapshots and Dockerfile `--mount=type=cache`
          // mounts onto the PVC, so they outlive the step instead of dying with the
          // throwaway daemon; --config applies the GC ceiling that keeps it bounded.
          {
            name: "BUILDKITD_FLAGS",
            value: [
              "--oci-worker-snapshotter=native",
              "--oci-worker-no-process-sandbox",
              `--root ${buildkitRoot}`,
              `--config ${buildkitConfig}`,
            ].join(" "),
          },
          { name: "CHAINS_IMAGE_URL_PATH", value: chains.urlPath },
          { name: "CHAINS_IMAGE_DIGEST_PATH", value: chains.digestPath },
          ...imageEnv,
        ],
        volumeMounts: [
          {
            name: "docker-config",
            mountPath: "/tmp/docker-auth/config.json",
            subPath: ".dockerconfigjson",
            readOnly: true,
          },
        ],
        onError: "continue",
        script,
      },
    ],
  });
}

// Per-image env consumed by build.sh / release.sh. TARGET is omitted for images
// without a Dockerfile target (e.g. web), so `$TARGET` is empty in the script.
// IMAGE_TITLE / IMAGE_DESCRIPTION feed the OCI title/description label+annotation.
function imageEnv(
  name: string,
  dockerfile: string,
  title: string,
  description: string,
  target?: string,
): EnvVar[] {
  const env: EnvVar[] = [
    { name: "IMAGE", value: `ghcr.io/pfenerty/ocidex-${name}` },
    { name: "DOCKERFILE", value: dockerfile },
    { name: "IMAGE_TITLE", value: title },
    { name: "IMAGE_DESCRIPTION", value: description },
  ];
  if (target) env.push({ name: "TARGET", value: target });
  return env;
}

// The single CI worker has limited spare CPU (~0.8 core free of 4), so the image builds
// run SEQUENTIALLY — each chained after the previous via `extraNeeds` — instead of in
// parallel, which overcommits the node and leaves pods Pending ("Insufficient cpu").
// The shared buildkit root (see buildImageTask) is what makes the serial order cheap:
// each build inherits the previous one's base image, module cache and builder-base.
type ImageSpec = [
  name: string,
  dockerfile: string,
  title: string,
  description: string,
  target?: string,
];
const imageSpecs: ImageSpec[] = [
  ["api", "docker/Dockerfile", "OCIDex API", "HTTP API server for SBOM metadata management", "api"],
  ["scanner-worker", "docker/Dockerfile", "OCIDex Scanner Worker", "OCI registry scanner and SBOM ingestion worker", "scanner-worker"],
  ["enrichment-worker", "docker/Dockerfile", "OCIDex Enrichment Worker", "SBOM enrichment pipeline dispatcher", "enrichment-worker"],
  ["oci-metadata-worker", "docker/Dockerfile", "OCIDex OCI Metadata Worker", "OCI image metadata enricher", "oci-metadata-worker"],
  ["git-worker", "docker/Dockerfile", "OCIDex Git Worker", "Git commit metadata enricher", "git-worker"],
  ["user-enricher-worker", "docker/Dockerfile", "OCIDex User Enricher Worker", "User-defined enrichment worker", "user-enricher-worker"],
  ["provenance-worker", "docker/Dockerfile", "OCIDex Provenance Worker", "OCI image provenance verification worker", "provenance-worker"],
  ["vuln-worker", "docker/Dockerfile", "OCIDex Vulnerability Worker", "Scheduled OSV.dev vulnerability store refresher", "vuln-worker"],
  ["web", "docker/web/Dockerfile", "OCIDex Web UI", "SolidJS frontend for OCIDex"],
  ["operator", "docker/Dockerfile", "OCIDex Operator", "Kubernetes operator for OCIDex CRDs", "operator"],
];

// Build a serial chain: task[i] runs after task[i-1]. Every task in a chain shares one
// buildkit root, which is what turns the serial ordering from a pure cost into a benefit:
// build[i] reuses the base image, module cache and builder-base that build[i-1] left behind,
// and recompiles only its own main package.
function serialChain(taskPrefix: string, script: ScriptInput, cacheWs: Workspace): Task[] {
  const chain: Task[] = [];
  for (const [name, dockerfile, title, description, target] of imageSpecs) {
    const after = chain.length ? [chain[chain.length - 1]] : [];
    chain.push(buildImageTask(`${taskPrefix}-${name}`, name, script, imageEnv(name, dockerfile, title, description, target), cacheWs, after));
  }
  return chain;
}

export const imageBuilds = serialChain("image-build", buildScript, buildkitCacheWs);
export const imageBuildsTag = serialChain("image-release", releaseScript, buildkitReleaseCacheWs);
