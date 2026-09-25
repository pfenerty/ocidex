import { Task, nu } from "@pfenerty/tektonic";
import { nodeImage, statusReporter } from "../../shared";

// Guard against pipeline drift. `make tekton-synth` runs only in dev, so nothing otherwise
// catches (a) a .tektonic/ edit that wasn't re-synthed, (b) a hand-edit to generated .tekton,
// (c) a broken synth, or (d) an orphan — a manifest .tektonic no longer emits but the cluster
// still applies. `tektonic check` re-synthesizes to a temp dir and diffs recursively, so it
// catches all four without asking git.
//
// It exits non-zero on drift, and a failing external raises in nushell, so the exit-code
// wrapper sees it — the earlier hand-rolled body's `exit 1` did not, and reported green on
// drift (ocidex-im4o.1).
export const tektonCheck = new Task({
  name: "tekton-check",
  statusReporter,
  steps: [
    {
      name: "synth-drift",
      image: nodeImage,
      computeResources: {
        limits: { cpu: "1", memory: "1Gi" },
        requests: { cpu: "200m", memory: "512Mi" },
      },
      script: nu`
cd .tektonic
^npm ci
^npx tektonic check
`,
    },
  ],
});
