import { Task, nu } from "@pfenerty/tektonic";
import { nodeImage, nodeModulesCache, nodeEnv, statusReporter } from "../../shared";
import { nodeSetup } from "../../script-lib";

export const frontendLint = new Task({
  name: "eslint-lint-web",
  statusReporter,
  caches: [nodeModulesCache],
  stepTemplate: {
    env: nodeEnv,
  },
  steps: [
    {
      name: "eslint-lint",
      image: nodeImage,
      workingDir: "$(workspaces.workspace.path)/web",
      computeResources: {
        limits: { cpu: "2", memory: "3Gi" },
        requests: { cpu: "500m", memory: "2Gi" },
      },
      script: nu`
${nodeSetup}
log "Running ESLint"
^npm run lint
log "OK: no lint errors"
`,
      onError: "continue",
    },
  ],
});
