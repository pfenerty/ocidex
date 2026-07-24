import { Task, sh } from "@pfenerty/tektonic";
import { reportOnlyStatusReporter, sourceBranchParam, uploadSarifStep } from "../../shared";
import { pacBaselineSh } from "../../script-lib";

// Multi-language SAST with Semgrep (Go + TypeScript + secrets rulesets). On a PR it scans
// diff-aware (only findings the branch adds vs its base) via --baseline-commit; on push it
// does a full scan. --error drives the report-only GitHub check; --sarif-output feeds the
// Security tab. Third-party image with no nushell, so this step is sh. Report-only:
// `onError: continue` keeps the PipelineRun green.
export const semgrep = new Task({
  name: "semgrep",
  params: [sourceBranchParam],
  statusReporter: reportOnlyStatusReporter,
  steps: [
    {
      name: "semgrep",
      image: "semgrep/semgrep:latest",
      // uid 1024 has no home dir, so $HOME defaults to `/` and semgrep can't create its
      // ~/.semgrep dir. Point HOME at world-writable /tmp (also the writable git global config).
      env: [{ name: "HOME", value: "/tmp" }],
      // --max-memory bounds per-rule/file usage; 3Gi limit leaves headroom for base + rules.
      computeResources: {
        limits: { cpu: "2", memory: "3Gi" },
        requests: { cpu: "500m", memory: "1Gi" },
      },
      script: sh`
${pacBaselineSh}
BASELINE=""
if [ -n "$BASELINE_REF" ]; then
  git -c safe.directory='*' update-ref refs/semgrep-baseline "$BASELINE_REF"
  BASELINE="--baseline-commit refs/semgrep-baseline"
fi
semgrep scan --error --disable-version-check --metrics off \
  --jobs 1 --max-memory 2048 \
  --config p/golang --config p/typescript --config p/secrets \
  --sarif-output=semgrep.sarif \
  $BASELINE .
`,
      onError: "continue",
    },
    uploadSarifStep("semgrep.sarif", "semgrep"),
  ],
});
