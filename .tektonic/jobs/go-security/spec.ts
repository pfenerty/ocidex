import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import {
  goImage,
  goEnv,
  goCache,
  reportOnlyStatusReporter,
  sourceBranchParam,
  uploadSarifStep,
} from "../../shared";

// Go dependency vulnerability scan. IMPORTANT: we catalog the *built binaries*, not
// go.sum. `syft dir:. --select-catalogers go` reads go.sum — the accumulated hash set
// for every module version ever seen during graph resolution — so grype then flags CVEs
// against dozens of phantom versions that aren't in the binary (e.g. 76 versions of
// golang.org/x/sys when the build selects exactly one). Building `./cmd/...` and letting
// syft's go-binary cataloger read the linker-embedded versions gives one version per
// module — the set we actually ship. govulncheck (jobs/go-vulncheck) adds reachability on
// top; this task is the broad SBOM/SARIF sweep. Report-only: the reporter posts the worst
// exit code as this task's GitHub check while the PipelineRun stays green.
export const goSecurity = new Task({
  name: "go-security",
  params: [sourceBranchParam],
  statusReporter: reportOnlyStatusReporter,
  caches: [goCache],
  stepTemplate: {
    env: goEnv,
  },
  steps: [
    {
      // Compile every command into .sbom-bins/ so syft catalogs the real linked module
      // set. Reuses the go module/build cache warmed by go-build.
      name: "build-bins",
      image: goImage,
      computeResources: {
        limits: { cpu: "2", memory: "2Gi", "ephemeral-storage": "4Gi" },
        requests: { cpu: "500m", memory: "1Gi", "ephemeral-storage": "2Gi" },
      },
      script: scriptFromFile(path.join(__dirname, "build.nu")),
    },
    {
      name: "sbom",
      image: "ghcr.io/pfenerty/apko-cicd/syft:1.45.1",
      computeResources: {
        limits: { cpu: "1", memory: "512Mi" },
        requests: { cpu: "200m", memory: "256Mi" },
      },
      script: scriptFromFile(path.join(__dirname, "sbom.sh")),
    },
    {
      name: "scan",
      image: "ghcr.io/pfenerty/apko-cicd/grype:0.114.0",
      computeResources: {
        limits: { cpu: "1", memory: "512Mi" },
        requests: { cpu: "200m", memory: "256Mi" },
      },
      script: scriptFromFile(path.join(__dirname, "scan.sh")),
    },
    uploadSarifStep("grype-go.sarif", "grype-go"),
  ],
});
