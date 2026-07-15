import * as path from "path";
import { ChainsImage, Task, ScriptInput, scriptFromFile } from "@pfenerty/tektonic";
import { statusReporter, dockerConfigVolume } from "../../shared";
import { goTest } from "../go-test/spec";
import { openapiCheck } from "../openapi-check/spec";

type EnvVar = { name: string; value: string };

// build.sh / release.sh are static and identical across images; per-image values
// (dockerfile, image name, optional target) are passed as step env vars.
const buildScript = scriptFromFile(path.join(__dirname, "build.sh"));
const releaseScript = scriptFromFile(path.join(__dirname, "release.sh"));

// Shared Task skeleton. Each image declares a ChainsImage (Tekton Chains build
// subject); build.sh/release.sh write the pushed ref + digest to its result paths.
// `extraNeeds` chains the builds serially (see serialChain).
function buildImageTask(
  taskName: string,
  imageName: string,
  script: ScriptInput,
  imageEnv: EnvVar[],
  extraNeeds: Task[] = [],
): Task {
  const chains = new ChainsImage({ name: imageName });
  return new Task({
    name: taskName,
    statusReporter,
    needs: [goTest, openapiCheck, ...extraNeeds],
    volumes: [dockerConfigVolume],
    results: [...chains.results],
    steps: [
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
          {
            name: "BUILDKITD_FLAGS",
            value:
              "--oci-worker-snapshotter=native --oci-worker-no-process-sandbox",
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

// The single CI worker has limited spare CPU (~0.8 core free of 4), so the five
// image builds run SEQUENTIALLY — each chained after the previous via `extraNeeds`
// — instead of 5-wide in parallel, which overcommits the node and leaves pods
// Pending ("Insufficient cpu"). The registry build cache keeps reruns fast.
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

// Build a serial chain: task[i] runs after task[i-1].
function serialChain(taskPrefix: string, script: ScriptInput): Task[] {
  const chain: Task[] = [];
  for (const [name, dockerfile, title, description, target] of imageSpecs) {
    const after = chain.length ? [chain[chain.length - 1]] : [];
    chain.push(buildImageTask(`${taskPrefix}-${name}`, name, script, imageEnv(name, dockerfile, title, description, target), after));
  }
  return chain;
}

export const imageBuilds = serialChain("image-build", buildScript);
export const imageBuildsTag = serialChain("image-release", releaseScript);
