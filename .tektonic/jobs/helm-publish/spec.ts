import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { statusReporter, dockerConfigVolume } from "../../shared";
import { imageBuilds } from "../image-build/spec";
import { helmCheck } from "../helm-check/spec";

export const helmPublish = new Task({
  name: "helm-publish",
  statusReporter,
  // helmCheck gates the publish: a chart that fails lint or the PodSecurity policies must
  // not reach the OCI registry Flux pulls from (ocidex-9yq4).
  needs: [...imageBuilds, helmCheck],
  volumes: [dockerConfigVolume],
  steps: [
    {
      name: "helm-package-push",
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
      script: scriptFromFile(path.join(__dirname, "publish.sh")),
    },
  ],
});
