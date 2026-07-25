import { Task, nu } from "@pfenerty/tektonic";
import { nodeImage, reportOnlyStatusReporter } from "../../shared";

// Guard against pipeline drift. `make tekton-synth` runs only in dev, so nothing otherwise
// catches (a) a .tektonic/ edit that wasn't re-synthed, (b) a hand-edit to generated .tekton,
// or (c) a broken synth — e.g. the Renovate typescript-v7 bump that broke ts-node and silently
// left .tekton stale. This regenerates .tekton in CI and fails if it differs from what's
// committed, or if synth errors.
//
// Report-only for the initial rollout (posts a red check without blocking the PipelineRun);
// swap to the blocking `statusReporter` once it's confirmed green.
export const tektonCheck = new Task({
  name: "tekton-check",
  statusReporter: reportOnlyStatusReporter,
  steps: [
    {
      name: "synth-drift",
      image: nodeImage,
      computeResources: {
        limits: { cpu: "1", memory: "1Gi" },
        requests: { cpu: "200m", memory: "512Mi" },
      },
      script: nu`
^git config --global --add safe.directory (pwd)
# npm normalizes github: deps to git+ssh in the lockfile; rewrite to anonymous https so
# npm ci can fetch the public @pfenerty/tektonic without SSH keys in CI.
^git config --global url."https://github.com/".insteadOf "ssh://git@github.com/"
cd .tektonic
^npm ci
^npx tsx pipeline.ts
cd ..
let drift = (^git status --porcelain -- .tekton | complete | get stdout | str trim)
if ($drift | is-not-empty) {
  print "✗ .tekton is out of sync with .tektonic/ — run 'make tekton-synth' and commit:"
  print $drift
  exit 1
}
print "✓ .tekton is in sync with .tektonic/"
`,
    },
  ],
});
