import * as path from "path";
import { ChainsImage, Task, scriptFromFile } from "@tektonic-ci/core";
import { statusReporter, dockerConfigVolume } from "../../shared";
import { imageBuildsTag } from "../image-build/spec";
import { helmCheck } from "../helm-check/spec";

// One Chains build subject per chart (ocidex-tkn9.10): Tekton Chains signs whatever a
// TaskRun reports in <name>-IMAGE_URL/-IMAGE_DIGEST results, and a chart in an OCI
// registry is an artifact like any image, so the charts get the same cosign signature
// and SLSA provenance as the images, with no signing key in this task.
const chartSubjects = {
  OCIDEX: new ChainsImage({ name: "chart-ocidex" }),
  OPERATOR: new ChainsImage({ name: "chart-ocidex-operator" }),
  AGENT: new ChainsImage({ name: "chart-ocidex-k8s-agent" }),
};

export const helmRelease = new Task({
  name: "helm-release",
  statusReporter,
  // helmCheck gates the release: a chart that fails lint or the PodSecurity policies must
  // not be tagged and pushed to the OCI registry (ocidex-9yq4).
  needs: [...imageBuildsTag, helmCheck],
  volumes: [dockerConfigVolume],
  results: Object.values(chartSubjects).flatMap((c) => c.results),
  steps: [
    {
      // Single step: resolve image digests, bake them into chart values, package,
      // and push — all under `set -e`, so a failed digest resolve aborts before any
      // chart is published (never ship a partially-pinned chart).
      name: "helm-package-push",
      image: "alpine/helm:4",
      workingDir: "$(workspaces.workspace.path)",
      onError: "continue",
      env: [
        { name: "DOCKER_CONFIG", value: "/tmp/helm-auth" },
        ...Object.entries(chartSubjects).flatMap(([key, c]) => [
          { name: `CHAINS_${key}_URL_PATH`, value: c.urlPath },
          { name: `CHAINS_${key}_DIGEST_PATH`, value: c.digestPath },
        ]),
      ],
      volumeMounts: [
        {
          name: "docker-config",
          mountPath: "/tmp/helm-auth/config.json",
          subPath: ".dockerconfigjson",
          readOnly: true,
        },
      ],
      script: scriptFromFile(path.join(__dirname, "release.sh")),
    },
  ],
});
