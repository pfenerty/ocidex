import {
  Workspace,
  GitHubStatusReporter,
  TaskVolumeSpec,
} from "@pfenerty/tektonic";

// --- Images ─────────────────────────────────────────────────────────────────
export const goImage = "ghcr.io/pfenerty/apko-cicd/golang:1.26";
export const nodeImage = "ghcr.io/pfenerty/apko-cicd/nodejs:24";

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
