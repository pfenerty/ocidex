import { Workspace, TaskVolumeSpec, TaskStepSpec, rawScript, PAC_PARAMS } from "@tektonic-ci/core";
import { GitHubStatusReporter } from "@tektonic-ci/reporter-github";

// --- Images ─────────────────────────────────────────────────────────────────
export const goImage = "ghcr.io/pfenerty/apko-cicd/golang:1.27";
// goImage plus gcc/glibc headers: `go test -race` needs cgo, and goImage has no C toolchain.
// About 3x goImage's size, so only go-test uses it. Bump in lockstep with goImage.
export const goCgoImage = "ghcr.io/pfenerty/apko-cicd/golang:1.27-cgo";
export const nodeImage = "ghcr.io/pfenerty/apko-cicd/nodejs:24";
export const baseImage = "ghcr.io/pfenerty/apko-cicd/base:stable";
// Go-version-matched govulncheck image; bump the -goX.Y suffix in lockstep with goImage.
export const govulncheckImage = "ghcr.io/pfenerty/apko-cicd/govulncheck:1.9.0-go1.27";
// SBOM + vuln scanners shared by the dependency-audit tasks (see jobs/_dep-scan.ts).
export const syftImage = "ghcr.io/pfenerty/apko-cicd/syft:1.51.0";
export const grypeImage = "ghcr.io/pfenerty/apko-cicd/grype:0.117.0";
// SAST + secrets scanners — first-party apko-cicd images (on base, so nushell + git are
// present), replacing Docker Hub semgrep/semgrep and zricethezav/gitleaks.
export const semgrepImage = "ghcr.io/pfenerty/apko-cicd/semgrep:1.165.0";
export const gitleaksImage = "ghcr.io/pfenerty/apko-cicd/gitleaks:8.30.1";
// Kyverno CLI + Helm in one image, so helm-check renders and validates in a single step.
// Not upstream's ghcr.io/kyverno/kyverno-cli: the cluster's ghcr-docker-config only covers
// pfenerty/*, and Kyverno publishes no Docker Hub mirror.
export const kyvernoImage = "ghcr.io/pfenerty/apko-cicd/kyverno:1.18.1-helm4";

// ─── Status reporter ─────────────────────────────────────────────────────────
export const statusReporter = new GitHubStatusReporter({
  tokenSecretName: "github-pipeline-token",
  // 5 tasks report status → 5 steps in set-status-pending, each just an HTTP POST.
  // Default 512Mi limit per step causes OOM on constrained nodes; these are tight
  // but sufficient for nushell + a single GitHub API call.
  pendingTaskComputeResources: {
    requests: { cpu: "25m", memory: "64Mi" },
    limits: { cpu: "200m", memory: "128Mi" },
  },
});

// Report-only variant for tasks whose findings should post a red GitHub check
// without failing the TaskRun/PipelineRun (e.g. security scans on push to main).
export const reportOnlyStatusReporter = new GitHubStatusReporter({
  tokenSecretName: "github-pipeline-token",
  pendingTaskComputeResources: {
    requests: { cpu: "25m", memory: "64Mi" },
    limits: { cpu: "200m", memory: "128Mi" },
  },
  failOnError: false,
});

// ─── Cache workspaces (PVC-backed, local-path) ───────────────────────────────
// Persistent PVCs provisioned once; mounted read-write by each pipeline run.
// ReadWriteOnce is required — local-path does not support ReadWriteMany.
// tektonic's save scripts write to a temp path and atomically rename into place
// (see pvc-backend.ts), so a killed/OOM'd save step or a concurrent save race can
// never leave a truncated archive at the hash-keyed cache path.
// The source checkout every task shares (GitPipeline's `workspace`). pipelines.ts hands this
// instance to each GitPipeline, so specs can build paths with sourceWs.at(...).
export const sourceWs = new Workspace({ name: "workspace" });
export const goCacheWs = new Workspace({ name: "go-cache" });
export const nodeCacheWs = new Workspace({ name: "node-cache" });

// buildkitd state directories (ocidex-2vr.2). Unlike goCacheWs/nodeCacheWs these are NOT
// used with tektonic's `caches:` restore/save archives — the PVC is mounted directly and
// buildkitd's --root points into it, so the content store, snapshots and the Dockerfile
// `--mount=type=cache` mounts survive both across the ten serial builds in one run and
// across runs. Without this, buildctl-daemonless.sh's throwaway daemon discards all of it
// every time, and each build re-pays the base pull + `go mod download` + builder-base.
//
// Two workspaces, not one: the push chain (linux/amd64) and the tag chain (multi-arch) are
// separate task chains that can overlap in wall-clock time, and buildkitd takes an
// exclusive lock on its root. Their cache contents differ anyway.
export const buildkitCacheWs = new Workspace({ name: "buildkit-cache" });
export const buildkitReleaseCacheWs = new Workspace({ name: "buildkit-release-cache" });

export const goCache = {
  name: "go-cache",
  key: ["go.sum"],
  // Use dotdir paths so `go test ./...` skips them (Go ignores dirs starting with '.')
  paths: [".go-mod", ".go-build"],
  workspace: goCacheWs,
  compress: true,
  workingDir: sourceWs.path,
};

// go-test runs after go-build on the same workspace PVC. go-build seeds .go-mod/.go-build,
// so restore must skip extraction when paths exist. forceSave ensures test-only deps are
// always written back (the archive may already exist from go-build's save).
export const goCacheTest = {
  ...goCache,
  forceSave: true,
  skipRestoreIfPathsExist: true,
};

// govulncheck-scan needs the same treatment, and for a sharper reason than go-test does
// (ocidex-plh). goEnv points GOMODCACHE/GOCACHE at two directories in the *shared* source
// workspace, so every Go task in the run reads and writes the same .go-mod/.go-build. A
// cache restore begins by `rm -rf`ing them. That is safe only while nothing else is using
// them — and govulncheck-scan is the one Go task Tekton may schedule at any moment, so its
// restore can land in the middle of another task's build. In ocidex-ocidex-push-hh77k it
// did: openapi-verify (which declares no cache of its own and just uses what go-build
// leaves behind) died with "package encoding/json is not in std" when the module cache
// vanished under it, and govulncheck's own `rm -rf` failed ENOTEMPTY against openapi-verify
// still writing. Skipping the restore when the paths are already populated removes the
// destructive step; go-vulncheck's `needs: [goBuild]` is what guarantees they are.
export const goCacheVulncheck = {
  ...goCache,
  skipRestoreIfPathsExist: true,
};

// go-integration-test runs after go-test but can still overlap go-lint, codegen-check and
// govulncheck-scan on the same shared .go-mod/.go-build. That is exactly the
// goCacheVulncheck situation: skipping the restore removes the destructive `rm -rf` that
// would otherwise land mid-build in another task, and go-test (after go-build) is what
// guarantees the paths are already populated. Concurrent
// *use* of GOCACHE/GOMODCACHE is fine — the go tool locks them. No forceSave: ./tests/...
// pulls in no module go-test hasn't already compiled, so there is nothing new to write back.
export const goCacheIntegration = {
  ...goCache,
  skipRestoreIfPathsExist: true,
};

// go-lint runs concurrently with go-test/go-integration-test on the shared .go-mod/.go-build,
// so it gets the goCacheVulncheck treatment: never restore over paths go-build populated.
// No forceSave: re-archiving the ~3.4GB shared tree took 2.5 min on every TaskRun, against
// ~90s to rebuild the pinned linter on a cold cache (tools/go.sum is not in the key). go-test
// force-saves the same shared tree, so the built linter is usually captured there anyway.
// The lint results themselves are in golangciLintCache, below. (ocidex-gyr0.3 TaskRuns)
export const goCacheLint = {
  ...goCache,
  skipRestoreIfPathsExist: true,
};

// golangci-lint's own analysis cache (GOLANGCI_LINT_CACHE in go-lint's env). Only go-lint
// touches it, so the restore guard below never actually skips anything in a fresh workspace;
// it is set to silence tektonic's shared-workspace default warning. forceSave keeps it
// current: entries are content-hashed per package, so an old archive only costs misses.
export const golangciLintCache = {
  name: "golangci-lint-cache",
  key: ["go.sum", "tools/go.sum", ".golangci.yml"],
  paths: [".golangci-cache"],
  workspace: goCacheWs,
  compress: true,
  workingDir: sourceWs.path,
  forceSave: true,
  skipRestoreIfPathsExist: true,
};

export const nodeModulesCache = {
  name: "node-modules",
  key: ["package-lock.json"],
  paths: ["node_modules"],
  workspace: nodeCacheWs,
  compress: true,
  workingDir: sourceWs.at("web"),
};

// ─── Env ─────────────────────────────────────────────────────────────────────
export const goEnv = [
  // uid 1024 has no passwd entry, so $HOME defaults to "/" and Go's default
  // GOPATH ("$HOME/go" = "/go") isn't writable. GOMODCACHE/GOCACHE cover the
  // module/build caches, but the sumdb tree-head cache is hardcoded to
  // "$GOPATH/pkg/sumdb" regardless of GOMODCACHE, so GOPATH must also point
  // at a writable location.
  { name: "GOPATH", value: sourceWs.at(".go-path") },
  { name: "GOMODCACHE", value: sourceWs.at(".go-mod") },
  { name: "GOCACHE", value: sourceWs.at(".go-build") },
  {
    name: "GIT_CONFIG_GLOBAL",
    value: sourceWs.at(".gitconfig"),
  },
];

// GOTMPDIR on the workspace PVC instead of the container's /tmp. A cold `go build`/`go list
// -export` keeps every compiled package in its $WORK dir until the command exits, so a cold
// golangci-lint run (export data for the whole module plus test deps) and a cold build of
// the pinned tools blow a 2Gi ephemeral-storage limit; the first go-lint TaskRun was evicted
// for exactly that (ocidex-gyr0.3). Dot dir, so ./... skips it. Go requires it to exist:
// steps using this env run goTmpSetup (script-lib.ts) first.
export const goTmpEnv = [{ name: "GOTMPDIR", value: sourceWs.at(".go-tmp") }];

export const nodeEnv = [{ name: "HOME", value: "/tmp" }];

// ─── Image build volume ──────────────────────────────────────────────────────
export const dockerConfigVolume: TaskVolumeSpec = {
  name: "docker-config",
  secret: { secretName: "ghcr-docker-config" },
};

// ─── SARIF → GitHub Security tab ──────────────────────────────────────────────
// Any task that uses `uploadSarifStep` declares PAC_PARAMS.sourceBranch for the git ref the
// code-scanning upload needs; `repo-full-name` + `revision` come for free on any task with a
// statusReporter.

// Best-effort SARIF upload to GitHub code-scanning (Security tab). Add as a trailing
// step on a report-only security task; it ALWAYS exits 0 so a failed/again-throttled
// upload never flips the task's own scan verdict. `category` keeps each tool's findings
// separate in the Security tab. Requires the `github-pipeline-token` secret to carry the
// `security-events: write` scope (in addition to repo:status used by the reporter).
export function uploadSarifStep(sarifPath: string, category: string): TaskStepSpec {
  return {
    name: `sarif-upload-${category}`,
    image: baseImage,
    env: [
      {
        name: "GITHUB_TOKEN",
        valueFrom: { secretKeyRef: { name: "github-pipeline-token", key: "token" } },
      },
    ],
    onError: "continue",
    // Uses `print` (a builtin) rather than the injected `log` helper: this is a raw shebang
    // body, which tektonic passes through verbatim with no wrapper. tektonic 2.x rejects a
    // bare '#!' string in a reporting task, hence rawScript(): the step never writes the
    // exit-code contract file, but it always exits 0 and the GitHub reporter also reads
    // Tekton's own per-step exit codes, so it cannot mask a failure.
    //
    // The body lives in `def main []` under a try/catch so that EVERY path reaches the
    // trailing `exit 0`, which is what the comment above has always claimed. It used not to:
    // a truncated SARIF failing `from json`, a missing `runs` field, or an absent `gzip` all
    // raised and the step exited 1. Since tektonic v1.3.0 the report-status step takes the
    // max over Tekton's own per-step exit codes, so that 1 would redden the *scan* check for
    // what is only an upload problem (ocidex-im4o.2).
    script: rawScript(`#!/usr/bin/env nu
def main [] {
print "upload-sarif [${category}]: start"

if not ("${sarifPath}" | path exists) or (ls "${sarifPath}" | get size.0) == 0B {
  print "upload-sarif [${category}]: no sarif produced, skipping"
  return
}

# code-scanning wants a full ref; PAC's source-branch is the short name on push, a ref on tag.
let ref_raw = "${PAC_PARAMS.sourceBranch}"
let ref = if ($ref_raw | str starts-with "refs/") { $ref_raw } else { $"refs/heads/($ref_raw)" }
print $"upload-sarif [${category}]: ref=($ref)"

# GitHub has no top-level category field (passing one returns 422). The category lives
# INSIDE the SARIF as runs[].automationDetails.id, which is also how GitHub keeps analyses
# distinct — essential here since grype-go and grype-web share the tool name grype and
# would otherwise overwrite each other on the same ref.
let sarif_json = (open --raw "${sarifPath}" | from json)
let ad = { id: "${category}/" }
let runs2 = ($sarif_json.runs | each { |r| $r | upsert automationDetails $ad })
let sarif_b64 = ($sarif_json | upsert runs $runs2 | to json -r | ^gzip -c | encode base64)
let url = "https://api.github.com/repos/${PAC_PARAMS.repoFullName}/code-scanning/sarifs"
let body = { commit_sha: "${PAC_PARAMS.revision}", ref: $ref, sarif: $sarif_b64 }

# --allow-errors + --full so a non-2xx (e.g. 403 missing security_events scope, 422 ref
# mismatch) is captured and logged instead of thrown — the status/body tells us exactly why.
# Wrapped in try only to survive genuine network errors. Note: interpolated strings must not
# contain bare parentheses (nushell evaluates them), so keep log text paren-free.
let resp = (try {
  http post $url $body -t application/json --full --allow-errors -H [
    Authorization $"token ($env.GITHUB_TOKEN)"
    Accept "application/vnd.github+json"
    X-GitHub-Api-Version "2022-11-28"
  ]
} catch { |e| print $"upload-sarif [${category}]: request error - ($e.msg)"; null })

if $resp != null {
  let status = ($resp.status? | default 0)
  if $status >= 200 and $status < 300 {
    print $"upload-sarif [${category}]: uploaded ok, status ($status)"
  } else {
    print $"upload-sarif [${category}]: upload failed, status ($status)"
    print ($resp.body? | default "" | to text)
  }
}
}

# Never affect the task's scan verdict: a malformed SARIF, a missing gzip, or any other raise
# inside main is logged and swallowed here rather than becoming the step's exit code.
try { main } catch { |e| print $"upload-sarif [${category}]: error - ($e.msg)" }
exit 0`),
  };
}
