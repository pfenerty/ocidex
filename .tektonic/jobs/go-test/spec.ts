import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { goImage, goCache, goEnv, statusReporter } from "../../shared";
import { goBuild } from "../go-build/spec";

// NOTE: The auto-generated cache steps in go-test.k8s.yaml have been manually
// patched. The restore step skips extraction when .go-mod already exists (go-build
// seeds it on the shared workspace PVC). The save step always overwrites the archive
// so test-only deps are included. Re-running `make tekton-synth` reverts these — re-apply.
export const goTest = new Task({
  name: "go-test",
  needs: [goBuild],
  caches: [goCache],
  statusReporter,
  stepTemplate: {
    env: [
      ...goEnv,
      { name: "GOMAXPROCS", value: "2" },
      { name: "GOMEMLIMIT", value: "1800MiB" },
    ],
  },
  steps: [
    {
      name: "test",
      image: goImage,
      computeResources: {
        // GKE Autopilot assigns ephemeral-storage: 1Gi by default; go test
        // writes compiled test binaries to $TMPDIR which can exceed that.
        // Request 2Gi so the container has room without routing to the PVC.
        limits: { cpu: "2", memory: "2Gi", "ephemeral-storage": "2Gi" },
        requests: {
          cpu: "500m",
          memory: "256Mi",
          "ephemeral-storage": "2Gi",
        },
      },
      script: scriptFromFile(path.join(__dirname, "test.nu")),
      onError: "continue",
    },
  ],
});
