import { Task, nu } from "@pfenerty/tektonic";
import { semgrepImage, reportOnlyStatusReporter, sourceBranchParam, uploadSarifStep } from "../../shared";
import { pacBaseline } from "../../script-lib";

// Multi-language SAST with Semgrep (Go + TypeScript + secrets rulesets). On a PR it scans
// diff-aware (only findings the branch adds vs its base) via --baseline-commit; on push it
// does a full scan. `--severity ERROR` limits it to high-severity rules, so the check fails
// only on high findings; --error drives the report-only GitHub check; --sarif-output feeds
// the Security tab. Runs on the first-party apko-cicd semgrep image (nushell + git present).
// Report-only: `onError: continue` keeps the PipelineRun green.
export const semgrep = new Task({
  name: "semgrep-sast",
  params: [sourceBranchParam],
  statusReporter: reportOnlyStatusReporter,
  steps: [
    {
      name: "semgrep-scan",
      image: semgrepImage,
      // uid 1024 has no home dir, so $HOME defaults to `/` and semgrep can't create its
      // ~/.semgrep dir. Point HOME at world-writable /tmp (also the writable git global config).
      env: [{ name: "HOME", value: "/tmp" }],
      // Full-repo scans on push OOMKilled at a 3Gi limit (semgrep-4pf): --max-memory 2048 caps
      // per-target work at 2Gi, but semgrep's base + rule-loading pushed the container past 3Gi.
      // Raise the limit to 4Gi for ~2Gi of headroom over the per-target cap. PR scans are
      // diff-aware (small) and never hit this; the ceiling is for the push full scan.
      computeResources: {
        limits: { cpu: "2", memory: "4Gi" },
        requests: { cpu: "500m", memory: "1Gi" },
      },
      script: nu`
${pacBaseline}
let baseline = if $scoped {
  ^git -c safe.directory='*' update-ref refs/semgrep-baseline FETCH_HEAD
  ["--baseline-commit" "refs/semgrep-baseline"]
} else { [] }
# Exclude the CI cache dirs goEnv creates in the workspace root (GOMODCACHE=.go-mod etc.):
# they hold tens of thousands of third-party .go files that semgrep would otherwise SAST-scan
# as if they were our source (66k+ files). .gitignore covers node_modules but not these.
^semgrep scan --error --disable-version-check --metrics off --jobs 1 --max-memory 2048 --severity ERROR --config p/golang --config p/typescript --config p/secrets --exclude .go-mod --exclude .go-build --exclude .go-path --sarif-output=semgrep.sarif ...$baseline .
`,
      onError: "continue",
    },
    uploadSarifStep("semgrep.sarif", "semgrep"),
  ],
});
