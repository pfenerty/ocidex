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

// Shared Task skeleton — only the script and per-image env differ.
function buildImageTask(taskName: string, imageName: string, script: ScriptInput, imageEnv: EnvVar[]): Task {
  // Tekton Chains build-subject hints: the build script writes the pushed image
  // reference and digest to these result paths (passed via env so build.sh/release.sh
  // stay shared across all images).
  const chains = new ChainsImage({ name: imageName });
  return new Task({
    name: taskName,
    statusReporter,
    needs: [goTest, openapiCheck],
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

function imageBuildTask(name: string, dockerfile: string, target?: string): Task {
  return buildImageTask(`image-build-${name}`, name, buildScript, imageEnv(name, dockerfile, target));
}

function imageBuildTagTask(name: string, dockerfile: string, target?: string): Task {
  return buildImageTask(`image-release-${name}`, name, releaseScript, imageEnv(name, dockerfile, target));
}

export const imageBuilds = [
  imageBuildTask("api", "docker/Dockerfile", "api"),
  imageBuildTask("scanner-worker", "docker/Dockerfile", "scanner-worker"),
  imageBuildTask("enrichment-worker", "docker/Dockerfile", "enrichment-worker"),
  imageBuildTask("web", "docker/web/Dockerfile"),
  imageBuildTask("operator", "docker/Dockerfile", "operator"),
];

export const imageBuildsTag = [
  imageBuildTagTask("api", "docker/Dockerfile", "api"),
  imageBuildTagTask("scanner-worker", "docker/Dockerfile", "scanner-worker"),
  imageBuildTagTask("enrichment-worker", "docker/Dockerfile", "enrichment-worker"),
  imageBuildTagTask("web", "docker/web/Dockerfile"),
  imageBuildTagTask("operator", "docker/Dockerfile", "operator"),
];
