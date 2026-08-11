import { Task, nu } from "@pfenerty/tektonic";
import { nodeImage, statusReporter } from "../../shared";

// Guard against pipeline drift. `make tekton-synth` runs only in dev, so nothing otherwise
// catches (a) a .tektonic/ edit that wasn't re-synthed, (b) a hand-edit to generated .tekton,
// or (c) a broken synth — e.g. the Renovate typescript-v7 bump that broke ts-node and silently
// left .tekton stale. This regenerates .tekton in CI and fails if it differs from what's
// committed, or if synth errors.
//
// Blocking since ocidex-es6. The report-only rollout's exit condition was "confirmed green on a
// PR" (PR #100, 2026-07-26) — but that signal was worthless: the body used `exit 1`, which meant
// the task reported success on drift too (see the error-make comment below). Both polarities are
// now verified by ad-hoc TaskRun: clean tree → Succeeded, injected un-synthed source bump →
// StepFailed with exit-code=1.
export const tektonCheck = new Task({
  name: "tekton-check",
  statusReporter,
  steps: [
    {
      name: "synth-drift",
      image: nodeImage,
      computeResources: {
        limits: { cpu: "1", memory: "1Gi" },
        requests: { cpu: "200m", memory: "512Mi" },
      },
      script: nu`
^git config --global --add safe.directory (pwd)
# npm normalizes github: deps to git+ssh in the lockfile; rewrite to anonymous https so
# npm ci can fetch the public @pfenerty/tektonic without SSH keys in CI.
^git config --global url."https://github.com/".insteadOf "ssh://git@github.com/"
cd .tektonic
# npm 12+ defaults allow-git to "none", blocking the @pfenerty/tektonic git dependency.
^npm ci --allow-git=all
^npx tsx pipeline.ts
cd ..
# Bind the whole record, not \`| get stdout\`: \`complete\` swallows the exit code, so a git
# that failed outright produced empty drift and a green check (ocidex-im4o.1).
let res = (^git status --porcelain -- .tekton | complete)
if $res.exit_code != 0 {
  print $res.stderr
  error make {msg: $"git status: exited ($res.exit_code)"}
}
let drift = ($res.stdout | str trim)
if ($drift | is-not-empty) {
  print "✗ .tekton is out of sync with .tektonic/ — run 'make tekton-synth' and commit:"
  print $drift
  # error make, NOT exit 1: tektonic wraps this body in a try/catch and persists the caught
  # code to /tekton/home/.exit-code, which the report-status step reads. nushell's exit kills
  # the process before that wrapper runs, so the file keeps its initial "0" and — with
  # onError: continue on this step — the task reports green on drift. error make throws, so
  # the wrapper sees it. Same reason gofmt-check raises instead of exiting.
  error make {msg: ".tekton is out of sync with .tektonic/"}
}
print "✓ .tekton is in sync with .tektonic/"
`,
    },
  ],
});
