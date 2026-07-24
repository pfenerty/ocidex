import { Task, sh } from "@pfenerty/tektonic";
import { reportOnlyStatusReporter } from "../../shared";
import { pacBaselineSh } from "../../script-lib";

// Secrets detection with gitleaks in git mode (scans tracked commits, so build/dep caches on
// the shared workspace are never scanned). On a PR it scans only the commits the branch adds
// vs its base; on push it scans full history. gitleaks exits non-zero on a leak, surfaced by
// the reporter as a failed check. Third-party image with no nushell, so this step is sh.
// Report-only: `onError: continue` keeps the PipelineRun green.
export const secretsScan = new Task({
  name: "gitleaks-secrets",
  statusReporter: reportOnlyStatusReporter,
  steps: [
    {
      name: "gitleaks-scan",
      image: "zricethezav/gitleaks:latest",
      // gitleaks shells out to git; HOME=/tmp keeps the global git config (safe.directory)
      // writable for uid 1024.
      env: [{ name: "HOME", value: "/tmp" }],
      computeResources: {
        limits: { cpu: "1", memory: "512Mi" },
        requests: { cpu: "100m", memory: "128Mi" },
      },
      script: sh`
${pacBaselineSh}
if [ -n "$BASELINE_REF" ]; then
  gitleaks git . --config .gitleaks.toml --redact --verbose --no-banner --log-opts="$BASELINE_REF..HEAD"
else
  gitleaks git . --config .gitleaks.toml --redact --verbose --no-banner
fi
`,
      onError: "continue",
    },
  ],
});
