import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { nodeImage, nodeModulesCache, nodeEnv, statusReporter } from "../../shared";

export const frontendLint = new Task({
  name: "frontend-lint",
  statusReporter,
  caches: [nodeModulesCache],
  stepTemplate: {
    env: nodeEnv,
  },
  steps: [
    {
      name: "lint",
      image: nodeImage,
      workingDir: "$(workspaces.workspace.path)/web",
      computeResources: {
        limits: { cpu: "2", memory: "3Gi" },
        requests: { cpu: "500m", memory: "2Gi" },
      },
      script: scriptFromFile(path.join(__dirname, "lint.nu")),
      onError: "continue",
    },
  ],
});
