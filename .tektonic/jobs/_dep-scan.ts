import { Task, nu, TaskStepSpec, TaskCacheSpec } from "@pfenerty/tektonic";
import {
  syftImage,
  grypeImage,
  reportOnlyStatusReporter,
  sourceBranchParam,
  uploadSarifStep,
} from "../shared";

// syft/grype steps are lightweight; the heavy lifting (if any) is in a preceding build step.
const scanResources = {
  limits: { cpu: "1", memory: "512Mi" },
  requests: { cpu: "200m", memory: "256Mi" },
};

export interface DepScanOptions {
  /** Task name, e.g. "go-security" / "web-security". */
  name: string;
  /** syft source argument, e.g. "dir:.sbom-bins" or "file:web/package-lock.json". */
  source: string;
  /** Optional syft --select-catalogers value, e.g. "go". */
  catalogers?: string;
  /** SBOM filename syft writes and grype reads. */
  sbom: string;
  /** SARIF category — also the "<category>.sarif" filename and Security-tab grouping id. */
  category: string;
  /** Steps to run before cataloging (e.g. compile Go binaries so syft reads real versions). */
  buildSteps?: TaskStepSpec[];
  /** Caches for the build step (e.g. goCache). */
  caches?: TaskCacheSpec[];
  /** stepTemplate env for the build step (e.g. goEnv). */
  env?: { name: string; value: string }[];
}

// Reusable syft → grype → SARIF dependency-vulnerability scan. The Go and frontend security
// tasks are the same shape; only the source, SBOM path, and SARIF category differ (Go also
// prepends a binary build). Report-only: grype's exit code becomes the GitHub check, the
// SARIF goes to the Security tab, and the PipelineRun stays green.
export function depScanTask(o: DepScanOptions): Task {
  const catalogerFlag = o.catalogers ? ` --select-catalogers ${o.catalogers}` : "";
  return new Task({
    name: o.name,
    params: [sourceBranchParam],
    statusReporter: reportOnlyStatusReporter,
    ...(o.caches ? { caches: o.caches } : {}),
    ...(o.env ? { stepTemplate: { env: o.env } } : {}),
    steps: [
      ...(o.buildSteps ?? []),
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
