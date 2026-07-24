import { nu, TaskStepSpec } from "@pfenerty/tektonic";
import { goImage, goEnv, goCache } from "../../shared";
import { goSetup } from "../../script-lib";
import { depScanTask } from "../_dep-scan";

// Compile every command into .sbom-bins/ so syft's go-binary cataloger reads the exact
// linker-embedded module versions (one per module) — NOT go.sum, which lists every version
// ever seen during graph resolution and floods grype with phantom findings. Reuses the go
// module/build cache warmed by go-build. govulncheck (jobs/go-vulncheck) adds reachability;
// this task is the broad SBOM/SARIF sweep.
const buildBins: TaskStepSpec = {
  name: "build-bins",
  image: goImage,
  computeResources: {
    limits: { cpu: "2", memory: "2Gi", "ephemeral-storage": "4Gi" },
    requests: { cpu: "500m", memory: "1Gi", "ephemeral-storage": "2Gi" },
  },
  script: nu`
${goSetup}
rm -rf .sbom-bins
mkdir .sbom-bins
log "building ./cmd/... into .sbom-bins/"
^go build -o .sbom-bins/ ./cmd/...
`,
};

export const goSecurity = depScanTask({
  name: "go-security",
  buildSteps: [buildBins],
  caches: [goCache],
  env: goEnv,
  source: "dir:.sbom-bins",
  catalogers: "go",
  sbom: "sbom.json",
  category: "grype-go",
});
