import { Task, nu } from "@pfenerty/tektonic";
import { gitleaksImage, reportOnlyStatusReporter } from "../../shared";
import { pacBaseline } from "../../script-lib";

// Secrets detection with gitleaks in git mode (scans tracked commits, so build/dep caches on
// the shared workspace are never scanned). On a PR it scans only the commits the branch adds
// vs its base; on push it scans full history. gitleaks exits non-zero on a leak, surfaced by
// the reporter as a failed check (a leaked secret is always high, so no severity gate).
// Runs on the first-party apko-cicd gitleaks image (nushell + git present). Report-only:
// `onError: continue` keeps the PipelineRun green.
export const secretsScan = new Task({
  name: "gitleaks-secrets",
  statusReporter: reportOnlyStatusReporter,
  steps: [
    {
      name: "gitleaks-scan",
      // gitleaks shells out to git; HOME=/tmp keeps the global git config (safe.directory)
      // writable for uid 1024.
      env: [{ name: "HOME", value: "/tmp" }],
      image: gitleaksImage,
      computeResources: {
        limits: { cpu: "1", memory: "512Mi" },
        requests: { cpu: "100m", memory: "128Mi" },
      },
      script: nu`
${pacBaseline}
let logopts = if $scoped { ["--log-opts=FETCH_HEAD..HEAD"] } else { [] }
^gitleaks git . --config .gitleaks.toml --redact --verbose --no-banner ...$logopts
`,
      onError: "continue",
    },
  ],
});
