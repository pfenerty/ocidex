import { Task, nu } from "@pfenerty/tektonic";
import { goImage, goCache, goEnv, statusReporter } from "../../shared";
import { goSetup } from "../../script-lib";

// Compile-check the representative binaries (each pulls in the shared internal/ packages, so
// this covers most of the build graph) and warm the go module/build cache for downstream go
// tasks. Builds to /dev/null — no artifact needed.
export const goBuild = new Task({
  name: "go-build",
  caches: [goCache],
  statusReporter,
  stepTemplate: {
    env: goEnv,
  },
  steps: [
    {
      name: "go-build",
      image: goImage,
      computeResources: {
        limits: { cpu: "2", memory: "2Gi", "ephemeral-storage": "4Gi" },
        requests: {
          cpu: "500m",
          memory: "1Gi",
          "ephemeral-storage": "2Gi",
        },
      },
      script: nu`
${goSetup}
for cmd in ["./cmd/ocidex" "./cmd/scanner-worker"] {
  log $"Building ($cmd)"
  ^go build -o /dev/null $cmd
}
log "OK: all binaries built"
`,
      onError: "continue",
    },
  ],
});
