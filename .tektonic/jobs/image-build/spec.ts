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
// The commit's own timestamp, used as build-arg:DATE. It must be identical across all ten
// builds in a chain or the shared build-all stage's RUN string differs per image and never
// hits CACHED (ocidex-2j2) — `date -u` at build time did exactly that. Kept OUTSIDE ctxDir so
// writing it does not perturb the build context.
const ctxDateFile = ".buildctx.date";

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
      // make that work without a chmod. Guarded on the revision so the ten subsequent
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

# Written unconditionally, outside the guard above: the extraction is skipped for builds
# 2..n of a chain, but the date file must still exist on a workspace that predates it.
with-env {TZ: "UTC"} {
  let created = (^git -c safe.directory='*' show -s --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ $rev | str trim)
  $created | save --force "${ctxDateFile}"
  log $"build-arg DATE pinned to commit time ($created)"
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
        // Limit was 2Gi, measured against the old one-binary-per-image Dockerfile: a single
        // linux/amd64 `api` build peaked at ~471Mi real memory (kubectl top, 10s sampling).
        // The build-all stage (ocidex-2j2) links ten main packages in one `go build`, several
        // concurrently, so the peak is higher; 3Gi covers that. Keep the ceiling tight enough
        // that a genuine burst hits this container's own OOMKilled instead of growing large
        // enough to trip Talos's node-wide OOMController (see ocidex-asx).
        computeResources: {
          requests: { cpu: "500m", memory: "1Gi" },
          limits: { cpu: "4", memory: "3Gi" },
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
// each build inherits the previous one's base image, module cache, builder-base and the
// build-all stage that holds every compiled binary.
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
  ["oci-metadata-worker", "docker/Dockerfile", "OCIDex OCI Metadata Worker", "OCI image metadata enricher", "oci-metadata-worker"],
  ["git-worker", "docker/Dockerfile", "OCIDex Git Worker", "Git commit metadata enricher", "git-worker"],
  ["user-enricher-worker", "docker/Dockerfile", "OCIDex User Enricher Worker", "User-defined enrichment worker", "user-enricher-worker"],
  ["provenance-worker", "docker/Dockerfile", "OCIDex Provenance Worker", "OCI image provenance verification worker", "provenance-worker"],
  ["vuln-worker", "docker/Dockerfile", "OCIDex Vulnerability Worker", "Scheduled OSV.dev vulnerability store refresher", "vuln-worker"],
  ["web", "docker/web/Dockerfile", "OCIDex Web UI", "SolidJS frontend for OCIDex"],
  ["operator", "docker/Dockerfile", "OCIDex Operator", "Kubernetes operator for OCIDex CRDs", "operator"],
  // Named "cli", not "ocidex-cli": imageEnv prefixes with `ocidex-`, so this publishes
  // ghcr.io/pfenerty/ocidex-cli alongside its nine siblings (ocidex-5dw).
  ["cli", "docker/Dockerfile", "OCIDex CLI", "Command-line client for OCIDex", "cli"],
];

// Build a serial chain: task[i] runs after task[i-1]. Every task in a chain shares one
// buildkit root, which is what turns the serial ordering from a pure cost into a benefit:
// build[0] runs docker/Dockerfile's build-all stage once, and build[1..n] hit it CACHED,
// doing nothing but copying their binary out of it and pushing the final image.
// This replaced nine per-binary stages that each cold-compiled the whole dependency graph
// (~210-300s apiece) because the builder image's GOCACHE never pointed at the cache mount
// (ocidex-2j2).
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
