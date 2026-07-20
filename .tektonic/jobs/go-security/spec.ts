import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { reportOnlyStatusReporter } from "../../shared";

// Go dependency vulnerability scan: syft catalogs the module graph straight from
// go.sum (no Go toolchain, no network — unlike the old `go run govulncheck@latest`,
// which downloaded+compiled the tool on every run), then grype scans that SBOM
// against known-vuln databases. gosec was dropped: it has no Wolfi apk package, and
// semgrep's `--config p/golang` ruleset (jobs/semgrep) already covers the same SAST
// categories (hardcoded creds, injection, weak crypto) with real but redundant
// overlap. Report-only: with statusReporter set, tektonic auto-injects
// `onError: continue` on every step so the reporter step always runs and posts the
// worst exit code across both steps as this task's GitHub check — the
// PipelineRun stays green either way.
export const goSecurity = new Task({
  name: "go-security",
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
  ],
});
