import { nu } from "@tektonic-ci/core";
import { semgrepImage, sarifScanTask, uploadSarifStep } from "../../shared";
import { pacBaseline, memoryWatchdog } from "../../script-lib";

// Multi-language SAST with Semgrep (Go + TypeScript + secrets rulesets). On a PR it scans
// diff-aware (only findings the branch adds vs its base) via --baseline-commit; on push it
// does a full scan. `--severity ERROR` limits it to high-severity rules, so the check fails
// only on high findings; --error drives the report-only GitHub check; --sarif-output feeds
// the Security tab. Runs on the first-party apko-cicd semgrep image (nushell + git present).
// Report-only: `onError: continue` keeps the PipelineRun green.
export const semgrep = sarifScanTask({
  name: "semgrep-sast",
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
      //
      // 4Gi is a ceiling, not a guarantee, and an OOMKill here would bypass this step's
      // `onError: continue` — Tekton treats it as an infrastructure failure, so the whole
      // PipelineRun hard-fails despite the report-only design. memoryWatchdog converts that
      // into exit 99, so a scan that runs out of memory reports red and the run stays green
      // (ocidex-im4o.3).
      computeResources: {
        limits: { cpu: "2", memory: "4Gi" },
        requests: { cpu: "500m", memory: "1Gi" },
      },
      script: nu`
${pacBaseline}
$env.SEMGREP_BASELINE = if $scoped {
  ^git -c safe.directory='*' update-ref refs/semgrep-baseline FETCH_HEAD
  "refs/semgrep-baseline"
} else { "" }
# Exclude the CI cache dirs goEnv creates in the workspace root (GOMODCACHE=.go-mod etc.):
# they hold tens of thousands of third-party .go files that semgrep would otherwise SAST-scan
# as if they were our source (66k+ files). .gitignore covers node_modules but not these.
# The scan runs under sh via memoryWatchdog, so the baseline crosses over as SEMGREP_BASELINE.
${memoryWatchdog(
  "semgrep",
  'semgrep scan --error --disable-version-check --metrics off --jobs 1 --max-memory 2048 --severity ERROR --config p/golang --config p/typescript --config p/secrets --exclude .go-mod --exclude .go-build --exclude .go-path --sarif-output=semgrep.sarif ${SEMGREP_BASELINE:+--baseline-commit "$SEMGREP_BASELINE"} .',
)}
`,
      onError: "continue",
    },
    uploadSarifStep("semgrep.sarif", "semgrep"),
  ],
});
