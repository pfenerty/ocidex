import {
    Task,
    Workspace,
    TaskCacheSpec,
    GitPipeline,
    TektonProject,
    TRIGGER_EVENTS,
    GitHubStatusReporter,
} from "@pfenerty/tektonic";

// --- Images ─────────────────────────────────────────────────────────────────
const goImage   = "ghcr.io/pfenerty/apko-cicd/golang:1.25";
const lintImage = "ghcr.io/pfenerty/apko-cicd/golangci-lint:2.11.4";
const nodeImage = "ghcr.io/pfenerty/apko-cicd/nodejs:22";

// ─── Status reporter ─────────────────────────────────────────────────────────
const statusReporter = new GitHubStatusReporter();

// ─── Cache workspaces (NFS RWX — persist across runs) ────────────────────────
const goCacheWs   = new Workspace({ name: "go-cache" });
const nodeCacheWs = new Workspace({ name: "node-cache" });

// ─── Cache specs ─────────────────────────────────────────────────────────────
// Compressed tarballs on NFS — one large sequential read/write per run instead
// of thousands of small NFS file operations. GOPATH/GOCACHE are placed inside
// the main workspace so Go tooling uses fast local-path storage during the run.
const nodeModulesCache: TaskCacheSpec = {
    key: ["web/package-lock.json"],
    paths: ["web/node_modules"],
    workspace: nodeCacheWs,
    image: nodeImage,
    compress: true,
    workingDir: "$(workspaces.workspace.path)",
};

// ─── Go env ──────────────────────────────────────────────────────────────────
// Point GOPATH/GOCACHE inside the workspace so the cache restore/save steps
// can manage them as relative paths. Actual builds run on local-path storage.
const goEnv = [
    { name: "GOPATH",  value: "$(workspaces.workspace.path)/.gopath" },
    { name: "GOCACHE", value: "$(workspaces.workspace.path)/.gocache" },
];

const lintEnv = [
    ...goEnv,
    { name: "GOLANGCI_LINT_CACHE", value: "$(workspaces.workspace.path)/.golangci-cache" },
];

// ─── Nushell helper ──────────────────────────────────────────────────────────
const nuHeader = `#!/usr/bin/env nu
def log [msg: string] { print $"[(date now | format date '%H:%M:%S')] ($msg)" }
def run_and_save [prev_ec: int, ...args: string] {
    try { run-external ...$args } catch { null }
    let ec = $env.LAST_EXIT_CODE
    let worst = if $prev_ec != 0 { $prev_ec } else { $ec }
    $"($worst)" | save -f /tekton/home/.exit-code
    $worst
}
`;

// ─── Tasks ──────────────────────────────────────────────────────────────────

const goCachePopulate = new Task({
    name: "go-cache-populate",
    workspaces: [goCacheWs],
    steps: [
        {
            name: "populate",
            image: goImage,
            workingDir: "$(workspaces.workspace.path)",
            computeResources: {
                limits: { cpu: "2", memory: "1Gi" },
                requests: { cpu: "500m", memory: "256Mi" },
            },
            env: goEnv,
            script: nuHeader + `
let cache_dir = "$(workspaces.go-cache.path)"
let workspace_dir = "$(workspaces.workspace.path)"
let hash = (open go.sum | hash sha256 | str substring 0..15)
let archive = $"($cache_dir)/($hash).tar.zst"
log $"Cache key: ($hash)"
if ($archive | path exists) {
    log "Cache hit — extracting archive"
    ^zstd -d $archive --stdout | ^tar -x -C $workspace_dir
    log "Done"
} else {
    log "Cache miss — downloading modules"
    ^go mod download all
    log "Saving cache archive"
    ^tar -c -C $workspace_dir ".gopath" ".gocache" | ^zstd -T2 - -o $archive
    log "Done"
}`,
        },
    ],
});

const goFmt = new Task({
    name: "go-fmt",
    params: [...statusReporter.requiredParams],
    statusContext: "ocidex/fmt",
    statusReporter,
    steps: [
        {
            name: "fmt",
            image: goImage,
            script: nuHeader + `
log "Checking gofmt"
let result = (^gofmt -l . | complete)
let ec = if ($result.stdout | str trim | str length) > 0 {
    print "Unformatted files:"; print $result.stdout; 1
} else { 0 }
$"($ec)" | save -f /tekton/home/.exit-code
log (if $ec == 0 { "OK: all files formatted" } else { "FAIL: formatting issues found" })
exit $ec`,
            onError: "continue",
        },
    ],
});

const goLint = new Task({
    name: "go-lint",
    params: [...statusReporter.requiredParams],
    needs: [goFmt],
    statusContext: "ocidex/lint",
    statusReporter,
    stepTemplate: {
        env: lintEnv,
    },
    steps: [
        {
            name: "lint",
            image: lintImage,
            computeResources: {
                limits: { cpu: "2", memory: "2Gi" },
                requests: { cpu: "200m", memory: "512Mi" },
            },
            script: nuHeader + `
log "Running golangci-lint"
let ec = run_and_save 0 "golangci-lint" "run" "./..."
log $"Exit code: ($ec)"
exit $ec`,
            onError: "continue",
        },
    ],
});

const goTest = new Task({
    name: "go-test",
    params: [...statusReporter.requiredParams],
    needs: [goLint, goCachePopulate],
    statusContext: "ocidex/test",
    statusReporter,
    stepTemplate: {
        env: [
            ...goEnv,
            { name: "GOMAXPROCS", value: "2" },
            { name: "GOMEMLIMIT", value: "1800MiB" },
        ],
    },
    steps: [
        {
            name: "test",
            image: goImage,
            computeResources: {
                limits: { cpu: "2", memory: "2Gi" },
                requests: { cpu: "500m", memory: "256Mi" },
            },
            script: nuHeader + `
if not ("$(workspaces.workspace.path)/.gopath" | path exists) {
    log "ERROR: .gopath missing — go-cache-populate task did not succeed"
    exit 1
}
log "Running go test"
let ec = run_and_save 0 "go" "test" "-v" "-short" "-p" "2" "./..."
log $"Exit code: ($ec)"
exit $ec`,
            onError: "continue",
        },
    ],
});

const goBuild = new Task({
    name: "go-build",
    params: [...statusReporter.requiredParams],
    needs: [goTest],
    statusContext: "ocidex/build",
    statusReporter,
    stepTemplate: {
        env: goEnv,
    },
    steps: [
        {
            name: "build",
            image: goImage,
            computeResources: {
                limits: { cpu: "2", memory: "2Gi" },
                requests: { cpu: "500m", memory: "256Mi" },
            },
            script: nuHeader + `
log "Building ocidex binaries"
mut ec = 0
for cmd in ["./cmd/ocidex", "./cmd/scanner-worker", "./cmd/enrichment-worker"] {
    log $"Building ($cmd)"
    $ec = (run_and_save $ec "go" "build" "-o" "/dev/null" $cmd)
}
log $"Exit code: ($ec)"
exit $ec`,
            onError: "continue",
        },
    ],
});

const openapiCheck = new Task({
    name: "openapi-check",
    params: [...statusReporter.requiredParams],
    needs: [goTest],
    caches: [nodeModulesCache],
    statusContext: "ocidex/openapi",
    statusReporter,
    steps: [
        {
            name: "check-spec",
            image: goImage,
            script: nuHeader + `
log "Generating OpenAPI spec"
try { ^go run ./cmd/specgen out> /tmp/openapi-check.json } catch { null }
let gen_ec = $env.LAST_EXIT_CODE
if $gen_ec != 0 {
    $"($gen_ec)" | save -f /tekton/home/.exit-code
    log $"FAIL: specgen exit ($gen_ec)"
    exit $gen_ec
}
log "Diffing against committed spec"
let ec = run_and_save 0 "diff" "web/openapi.json" "/tmp/openapi-check.json"
log (if $ec == 0 { "OK: spec is up to date" } else { "FAIL: spec out of date" })
exit $ec`,
            onError: "continue",
        },
        {
            name: "check-types",
            image: nodeImage,
            workingDir: "$(workspaces.workspace.path)/web",
            script: nuHeader + `
let prev_ec = (open /tekton/home/.exit-code | str trim | into int)
log "Generating TypeScript types from spec"
try { ^npx openapi-typescript openapi.json -o /tmp/openapi-check.d.ts } catch { null }
let gen_ec = $env.LAST_EXIT_CODE
if $gen_ec != 0 {
    let ec = if $prev_ec != 0 { $prev_ec } else { $gen_ec }
    $"($ec)" | save -f /tekton/home/.exit-code
    exit $ec
}
log "Diffing against committed types"
let ec = run_and_save $prev_ec "diff" "src/types/openapi.d.ts" "/tmp/openapi-check.d.ts"
log (if $ec == 0 { "OK: types up to date" } else { "FAIL: types out of date" })
exit $ec`,
            onError: "continue",
        },
    ],
});

const frontendLint = new Task({
    name: "frontend-lint",
    params: [...statusReporter.requiredParams],
    needs: [openapiCheck],
    caches: [nodeModulesCache],
    statusContext: "ocidex/frontend-lint",
    statusReporter,
    steps: [
        {
            name: "lint",
            image: nodeImage,
            workingDir: "$(workspaces.workspace.path)/web",
            script: nuHeader + `
log "Running ESLint"
let ec = run_and_save 0 "npm" "run" "lint"
log (if $ec == 0 { "OK: no lint errors" } else { "FAIL: lint errors found" })
exit $ec`,
            onError: "continue",
        },
    ],
});

// ─── Pipelines ──────────────────────────────────────────────────────────────

const allTasks = [goCachePopulate, goFmt, goLint, goTest, goBuild, openapiCheck, frontendLint];

const pushPipeline = new GitPipeline({
    name: "ocidex-push",
    triggers: [TRIGGER_EVENTS.PUSH],
    tasks: allTasks,
});

const prPipeline = new GitPipeline({
    name: "ocidex-pull-request",
    triggers: [TRIGGER_EVENTS.PULL_REQUEST],
    tasks: allTasks,
});

// ─── Synthesize ─────────────────────────────────────────────────────────────
new TektonProject({
    name: "ocidex",
    namespace: "ocidex-ci",
    pipelines: [pushPipeline, prPipeline],
    outdir: "generated",
    webhookSecretRef: {
        secretName: "github-webhook-secret",
        secretKey: "secret",
    },
    workspaceStorageClass: "local-path",
    defaultPodSecurityContext: {
        runAsUser: 1024,
        runAsGroup: 1024,
        fsGroup: 1024,
    },
    // Cache PVCs on NFS (RWX) — persist compressed tarballs across runs.
    // Pods run as uid 1024 to match NFS all_squash anonuid.
    caches: [
        { workspace: goCacheWs,   storageSize: "5Gi", storageClassName: "nfs-client" },
        { workspace: nodeCacheWs, storageSize: "2Gi", storageClassName: "nfs-client" },
    ],
});
