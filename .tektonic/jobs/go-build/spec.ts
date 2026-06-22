import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { goImage, goCache, goEnv, statusReporter } from "../../shared";

export const goBuild = new Task({
  name: "go-build",
  caches: [goCache],
  statusReporter,
  stepTemplate: {
    env: goEnv,
  },
  steps: [
    {
      name: "build",
      image: goImage,
      computeResources: {
        limits: { cpu: "2", memory: "2Gi", "ephemeral-storage": "4Gi" },
        requests: {
          cpu: "500m",
          memory: "1Gi",
          "ephemeral-storage": "2Gi",
        },
      },
      script: scriptFromFile(path.join(__dirname, "build.nu")),
      onError: "continue",
    },
  ],
});
