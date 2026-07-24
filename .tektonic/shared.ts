import {
  Param,
  Workspace,
  GitHubStatusReporter,
  TaskVolumeSpec,
  TaskStepSpec,
} from "@pfenerty/tektonic";

// --- Images ─────────────────────────────────────────────────────────────────
export const goImage = "ghcr.io/pfenerty/apko-cicd/golang:1.26";
export const nodeImage = "ghcr.io/pfenerty/apko-cicd/nodejs:24";
export const baseImage = "ghcr.io/pfenerty/apko-cicd/base:stable";
// Go-version-matched govulncheck image; bump the -goX.Y suffix in lockstep with goImage.
export const govulncheckImage = "ghcr.io/pfenerty/apko-cicd/govulncheck:1.6.0-go1.26";

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
export const goCacheWs = new Workspace({ name: "go-cache" });
export const nodeCacheWs = new Workspace({ name: "node-cache" });

export const goCache = {
  name: "go-cache",
  key: ["go.sum"],
  // Use dotdir paths so `go test ./...` skips them (Go ignores dirs starting with '.')
  paths: [".go-mod", ".go-build"],
  workspace: goCacheWs,
  compress: true,
  workingDir: "$(workspaces.workspace.path)",
};

// go-test runs after go-build on the same workspace PVC. go-build seeds .go-mod/.go-build,
// so restore must skip extraction when paths exist. forceSave ensures test-only deps are
// always written back (the archive may already exist from go-build's save).
export const goCacheTest = {
  ...goCache,
  forceSave: true,
  skipRestoreIfPathsExist: true,
};

export const nodeModulesCache = {
  name: "node-modules",
  key: ["package-lock.json"],
  paths: ["node_modules"],
  workspace: nodeCacheWs,
  compress: true,
  workingDir: "$(workspaces.workspace.path)/web",
};

// ─── Env ─────────────────────────────────────────────────────────────────────
export const goEnv = [
  // uid 1024 has no passwd entry, so $HOME defaults to "/" and Go's default
  // GOPATH ("$HOME/go" = "/go") isn't writable. GOMODCACHE/GOCACHE cover the
  // module/build caches, but the sumdb tree-head cache is hardcoded to
  // "$GOPATH/pkg/sumdb" regardless of GOMODCACHE, so GOPATH must also point
  // at a writable location.
  { name: "GOPATH", value: "$(workspaces.workspace.path)/.go-path" },
  { name: "GOMODCACHE", value: "$(workspaces.workspace.path)/.go-mod" },
  { name: "GOCACHE", value: "$(workspaces.workspace.path)/.go-build" },
  {
    name: "GIT_CONFIG_GLOBAL",
    value: "$(workspaces.workspace.path)/.gitconfig",
  },
];

export const nodeEnv = [{ name: "HOME", value: "/tmp" }];

// ─── Image build volume ──────────────────────────────────────────────────────
export const dockerConfigVolume: TaskVolumeSpec = {
  name: "docker-config",
  secret: { secretName: "ghcr-docker-config" },
};

// ─── SARIF → GitHub Security tab ──────────────────────────────────────────────
// Declare this Param on any task that uses `uploadSarifStep` so the git ref is
// available for the code-scanning upload. tektonic wires it from the pipeline's
// `source-branch` ({{ source_branch }}); `repo-full-name` + `revision` come for free
// on any task with a statusReporter.
export const sourceBranchParam = new Param({ name: "source-branch", type: "string" });

// Best-effort SARIF upload to GitHub code-scanning (Security tab). Add as a trailing
// step on a report-only security task; it ALWAYS exits 0 so a failed/again-throttled
// upload never flips the task's own scan verdict. `category` keeps each tool's findings
// separate in the Security tab. Requires the `github-pipeline-token` secret to carry the
// `security-events: write` scope (in addition to repo:status used by the reporter).
export function uploadSarifStep(sarifPath: string, category: string): TaskStepSpec {
  return {
    name: `upload-sarif-${category}`,
    image: baseImage,
    env: [
      {
        name: "GITHUB_TOKEN",
        valueFrom: { secretKeyRef: { name: "github-pipeline-token", key: "token" } },
      },
    ],
    onError: "continue",
    // Uses `print` (a builtin) rather than the injected `log` helper, and exits 0 so this
    // step never raises the task's accumulated exit code (the scan step's verdict stands).
    script: `#!/usr/bin/env nu
print "upload-sarif [${category}]: start"

if not ("${sarifPath}" | path exists) or (ls "${sarifPath}" | get size.0) == 0B {
  print "upload-sarif [${category}]: no sarif produced, skipping"
  exit 0
}

# code-scanning wants a full ref; PAC's source-branch is the short name on push, a ref on tag.
let ref_raw = "$(params.source-branch)"
let ref = if ($ref_raw | str starts-with "refs/") { $ref_raw } else { $"refs/heads/($ref_raw)" }
print $"upload-sarif [${category}]: ref=($ref)"

let sarif_b64 = (open --raw "${sarifPath}" | ^gzip -c | encode base64)
let url = "https://api.github.com/repos/$(params.repo-full-name)/code-scanning/sarifs"
let body = { commit_sha: "$(params.revision)", ref: $ref, sarif: $sarif_b64, category: "${category}" }

try {
  http post $url $body -t application/json -H [
    Authorization $"token ($env.GITHUB_TOKEN)"
    Accept "application/vnd.github+json"
    X-GitHub-Api-Version "2022-11-28"
  ]
  print "upload-sarif [${category}]: uploaded"
} catch { |e| print $"upload-sarif [${category}]: upload failed (non-fatal): ($e.msg)" }

# Never affect the task's scan verdict.
exit 0`,
  };
}
