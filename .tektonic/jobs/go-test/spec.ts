import * as path from "path";
import { Task, scriptFromFile } from "@tektonic-ci/core";
import { goCgoImage, goCacheTest, goEnv, goTmpEnv, statusReporter } from "../../shared";
import { goBuild } from "../go-build/spec";

export const goTest = new Task({
  name: "go-test",
  needs: [goBuild],
  caches: [goCacheTest],
  statusReporter,
  stepTemplate: {
    env: [
      ...goEnv,
      ...goTmpEnv,
      // -race needs cgo (ocidex-gyr0.4).
      { name: "CGO_ENABLED", value: "1" },
      { name: "GOMAXPROCS", value: "2" },
      // Caps the Go heap only. The race detector's shadow memory is allocated outside it,
      // which is what the headroom between this and the 6Gi limit is for.
      { name: "GOMEMLIMIT", value: "3GiB" },
    ],
  },
  steps: [
    {
      name: "go-test",
      image: goCgoImage,
      computeResources: {
        // -race multiplies test memory (5-10x is typical), hence 6Gi; sized from the
        // ocidex-gyr0.4 TaskRun. Compiled test binaries go to GOTMPDIR on the workspace
        // PVC (goTmpEnv), so ephemeral storage only covers logs and small temp files.
        limits: { cpu: "2", memory: "6Gi", "ephemeral-storage": "1Gi" },
        requests: {
          cpu: "500m",
          memory: "1Gi",
          "ephemeral-storage": "256Mi",
        },
      },
      script: scriptFromFile(path.join(__dirname, "test.nu")),
      onError: "continue",
    },
  ],
});
