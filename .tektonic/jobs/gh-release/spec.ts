import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { statusReporter } from "../../shared";
import { imageBuildsTag } from "../image-build/spec";

export const ghRelease = new Task({
  name: "gh-release",
  statusReporter,
  needs: [...imageBuildsTag],
  steps: [
    {
      name: "create-release",
      image: "ghcr.io/pfenerty/apko-cicd/base:stable",
      workingDir: "$(workspaces.workspace.path)",
      onError: "continue",
      env: [
        {
          name: "GH_TOKEN",
          valueFrom: { secretKeyRef: { name: "github-pipeline-token", key: "token" } },
        },
      ],
      script: scriptFromFile(path.join(__dirname, "create-release.nu")),
    },
  ],
});
