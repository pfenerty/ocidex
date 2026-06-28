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
        computeResources: {
          requests: { cpu: "500m", memory: "1Gi" },
          limits: { cpu: "4", memory: "4Gi" },
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
function imageEnv(name: string, dockerfile: string, target?: string): EnvVar[] {
  const env: EnvVar[] = [
    { name: "IMAGE", value: `ghcr.io/pfenerty/ocidex-${name}` },
    { name: "DOCKERFILE", value: dockerfile },
  ];
  if (target) env.push({ name: "TARGET", value: target });
  return env;
}

// The single CI worker has limited spare CPU (~0.8 core free of 4), so the five
// image builds run SEQUENTIALLY — each chained after the previous via `extraNeeds`
// — instead of 5-wide in parallel, which overcommits the node and leaves pods
// Pending ("Insufficient cpu"). The registry build cache keeps reruns fast.
type ImageSpec = [name: string, dockerfile: string, target?: string];
const imageSpecs: ImageSpec[] = [
  ["api", "docker/Dockerfile", "api"],
  ["scanner-worker", "docker/Dockerfile", "scanner-worker"],
  ["enrichment-worker", "docker/Dockerfile", "enrichment-worker"],
  ["oci-metadata-worker", "docker/Dockerfile", "oci-metadata-worker"],
  ["user-enricher-worker", "docker/Dockerfile", "user-enricher-worker"],
  ["provenance-worker", "docker/Dockerfile", "provenance-worker"],
  ["web", "docker/web/Dockerfile"],
  ["operator", "docker/Dockerfile", "operator"],
];

// Build a serial chain: task[i] runs after task[i-1].
function serialChain(taskPrefix: string, script: ScriptInput): Task[] {
  const chain: Task[] = [];
  for (const [name, dockerfile, target] of imageSpecs) {
    const after = chain.length ? [chain[chain.length - 1]] : [];
    chain.push(buildImageTask(`${taskPrefix}-${name}`, name, script, imageEnv(name, dockerfile, target), after));
  }
  return chain;
}

export const imageBuilds = serialChain("image-build", buildScript);
export const imageBuildsTag = serialChain("image-release", releaseScript);
