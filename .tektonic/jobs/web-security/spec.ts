import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { reportOnlyStatusReporter, sourceBranchParam, uploadSarifStep } from "../../shared";

// Node/TS dependency vulnerability scan for the SolidJS frontend (web/). Previously the
// frontend's deps were never vuln-scanned — frontend-lint runs eslint only. syft catalogs
// the npm graph straight from web/package-lock.json (no install, no network) → grype scans
// that SBOM. Mirrors go-security's syft→grype→SARIF flow so Go and Node share one
// toolchain and one Security-tab pipeline. Report-only.
export const webSecurity = new Task({
  name: "web-security",
  params: [sourceBranchParam],
  statusReporter: reportOnlyStatusReporter,
  steps: [
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
    uploadSarifStep("grype-web.sarif", "grype-web"),
  ],
});
