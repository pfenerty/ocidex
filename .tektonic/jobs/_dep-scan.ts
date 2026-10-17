import { nu } from "@tektonic-ci/core";
import { syftImage, grypeImage, sarifScanTask, uploadSarifStep } from "../shared";

// syft/grype steps are lightweight: they read a lockfile or SBOM, nothing is compiled here.
const scanResources = {
  limits: { cpu: "1", memory: "512Mi" },
  requests: { cpu: "200m", memory: "256Mi" },
};

export interface DepScanOptions {
  /** Task name, e.g. "grype-vuln-web". */
  name: string;
  /** syft source argument, e.g. "file:web/package-lock.json". */
  source: string;
  /** Optional syft --select-catalogers value, e.g. "javascript". */
  catalogers?: string;
  /** SBOM filename syft writes and grype reads. */
  sbom: string;
  /** SARIF category — also the "<category>.sarif" filename and Security-tab grouping id. */
  category: string;
}

// Reusable syft → grype → SARIF dependency-vulnerability scan, on the report-only
// sarifScanTask preset: grype's exit code becomes the GitHub check, the SARIF goes to the
// Security tab, and the PipelineRun stays green. Only the frontend uses it; Go deps go
// through govulncheck instead (see pipelines.ts).
export function depScanTask(o: DepScanOptions) {
  const catalogerFlag = o.catalogers ? ` --select-catalogers ${o.catalogers}` : "";
  return sarifScanTask({
    name: o.name,
    steps: [
      {
        name: "syft-sbom",
        image: syftImage,
        computeResources: scanResources,
        script: nu`
          print "syft: cataloging ${o.source} -> ${o.sbom}"
          ^syft ${o.source}${catalogerFlag} -o json=${o.sbom}
        `,
      },
      {
        name: "grype-scan",
        image: grypeImage,
        computeResources: scanResources,
        script: nu`
          print "grype: scanning ${o.sbom} (fail-on high); SARIF -> ${o.category}.sarif"
          ^grype sbom:${o.sbom} --fail-on high -o table -o sarif=${o.category}.sarif
        `,
      },
      uploadSarifStep(`${o.category}.sarif`, o.category),
    ],
  });
}
