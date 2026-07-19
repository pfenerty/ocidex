import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { statusReporter, dockerConfigVolume } from "../../shared";
import { imageBuildsTag } from "../image-build/spec";

export const helmRelease = new Task({
  name: "helm-release",
  statusReporter,
  needs: [...imageBuildsTag],
  volumes: [dockerConfigVolume],
  steps: [
    {
      // Single step: resolve image digests, bake them into chart values, package,
      // and push — all under `set -e`, so a failed digest resolve aborts before any
      // chart is published (never ship a partially-pinned chart).
      name: "package-and-push",
      image: "alpine/helm:4",
      workingDir: "$(workspaces.workspace.path)",
      onError: "continue",
      env: [{ name: "DOCKER_CONFIG", value: "/tmp/helm-auth" }],
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
