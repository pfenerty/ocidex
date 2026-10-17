import * as path from "path";
import { Task, scriptFromFile } from "@tektonic-ci/core";
import { goImage, goCacheLint, golangciLintCache, goEnv, goTmpEnv, statusReporter } from "../../shared";
import { goBuild } from "../go-build/spec";

// golangci-lint over the whole module (ocidex-gyr0.3). needs: [goBuild] for cache warmth and
// because goCacheLint's skipRestoreIfPathsExist relies on go-build having populated the
// shared .go-mod/.go-build (see goCacheVulncheck in shared.ts for why restoring under a
// running Go task is destructive).
export const goLint = new Task({
  name: "go-lint",
  needs: [goBuild],
  caches: [goCacheLint, golangciLintCache],
  statusReporter,
  stepTemplate: {
    env: [
      ...goEnv,
      ...goTmpEnv,
      { name: "GOLANGCI_LINT_CACHE", value: "$(workspaces.workspace.path)/.golangci-cache" },
      { name: "GOMAXPROCS", value: "2" },
      { name: "GOMEMLIMIT", value: "3500MiB" },
    ],
  },
  steps: [
    {
      name: "go-lint",
      image: goImage,
      computeResources: {
        // Type-checking every package with ~20 linters loaded holds the whole module's SSA
        // in memory; this is the starting size from the story, tune from TaskRun usage.
        limits: { cpu: "2", memory: "4Gi", "ephemeral-storage": "2Gi" },
        requests: { cpu: "500m", memory: "2Gi", "ephemeral-storage": "2Gi" },
      },
      script: scriptFromFile(path.join(__dirname, "lint.nu")),
      onError: "continue",
    },
  ],
});
