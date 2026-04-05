import {
    Task,
    GitPipeline,
    TektonProject,
    TRIGGER_EVENTS,
    GitHubStatusReporter,
} from "@pfenerty/tektonic";

// --- Images ─────────────────────────────────────────────────────────────────
const goImage = "ghcr.io/pfenerty/apko-cicd/golang:1.25";
const lintImage = "ghcr.io/pfenerty/apko-cicd/golangci-lint:2.11.4-go1.25";
const nodeImage = "ghcr.io/pfenerty/apko-cicd/nodejs:22";

// ─── Status reporter ─────────────────────────────────────────────────────────
const statusReporter = new GitHubStatusReporter();

// ─── Cache specs (GCS — no PVCs needed) ─────────────────────────────────────
// Archives stored in gs://ocidex-ci-cache/{go,node}/HASH.tar.zst.
// Auth via GKE Workload Identity (serviceAccountAnnotations below).
const goCache = {
    name: "go-cache",
    key: ["go.sum"],
    // Use dotdir paths so `go test ./...` skips them (Go ignores dirs starting with '.')
    paths: [".go-mod", ".go-build"],
    backend: { type: "gcs" as const, bucket: "ocidex-ci-cache", prefix: "go/" },
    compress: true,
    workingDir: "$(workspaces.workspace.path)",
};

const nodeModulesCache = {
    name: "node-modules",
    key: ["package-lock.json"],
    paths: ["node_modules"],
    backend: {
        type: "gcs" as const,
        bucket: "ocidex-ci-cache",
        prefix: "node/",
    },
    compress: true,
    workingDir: "$(workspaces.workspace.path)/web",
};

// ─── Go env ──────────────────────────────────────────────────────────────────
const goEnv = [
    { name: "GOMODCACHE", value: "$(workspaces.workspace.path)/.go-mod" },
    { name: "GOCACHE", value: "$(workspaces.workspace.path)/.go-build" },
    {
        name: "GIT_CONFIG_GLOBAL",
        value: "$(workspaces.workspace.path)/.gitconfig",
    },
];

const lintEnv = [
    ...goEnv,
    {
        name: "GOLANGCI_LINT_CACHE",
        value: "$(workspaces.workspace.path)/.golangci-cache",
    },
];

const nodeEnv = [{ name: "HOME", value: "$(workspaces.workspace.path)" }];

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
const goFmt = new Task({
    name: "go-fmt",
    statusReporter,
    steps: [
        {
            name: "fmt",
            image: goImage,
            script:
                nuHeader +
                `
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

const goBuild = new Task({
    name: "go-build",
    caches: [goCache],
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
            script:
                nuHeader +
                `
log $"pwd=(pwd) uid=(id -u) go=(go version)"
log $"GOMODCACHE=($env.GOMODCACHE) GOCACHE=($env.GOCACHE)"
log $".git exists=('.git' | path exists) go-mod exists=('go-mod' | path exists)"
^git config --global --add safe.directory (pwd)
log $"git rev-parse HEAD: (^git rev-parse --short HEAD)"
log "Building ocidex binaries"
mut ec = 0
for cmd in ["./cmd/ocidex", "./cmd/scanner-worker", "./cmd/enrichment-worker"] {
    log $"Building ($cmd)"
    $ec = (run_and_save $ec "go" "build" "-o" "/dev/null" $cmd)
    log $"  -> exit ($ec)"
}
log $"Exit code: ($ec)"
exit $ec`,
            onError: "continue",
        },
    ],
});

const goTest = new Task({
    name: "go-test",
    needs: [goBuild],
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
                // GKE Autopilot assigns ephemeral-storage: 1Gi by default; go test
                // writes compiled test binaries to $TMPDIR which can exceed that.
                // Request 2Gi so the container has room without routing to the PVC.
                limits: { cpu: "2", memory: "2Gi", "ephemeral-storage": "2Gi" },
                requests: {
                    cpu: "500m",
                    memory: "256Mi",
                    "ephemeral-storage": "2Gi",
                },
            },
            script:
                nuHeader +
                `
log "Running go test"
let ec = run_and_save 0 "go" "test" "-v" "-short" "-p" "2" "./..."
log $"Exit code: ($ec)"
exit $ec`,
            onError: "continue",
        },
    ],
});

const frontendLint = new Task({
    name: "frontend-lint",
    statusReporter,
    caches: [nodeModulesCache],
    stepTemplate: {
        env: nodeEnv,
    },
    steps: [
        {
            name: "lint",
            image: nodeImage,
            workingDir: "$(workspaces.workspace.path)/web",
            computeResources: {
                limits: { cpu: "2", memory: "3Gi" },
                requests: { cpu: "1", memory: "2Gi" },
            },
            script:
                nuHeader +
                `
log $"pwd=(pwd) uid=(id -u) node=(node --version) npm=(npm --version)"
log $"node_modules exists=('node_modules' | path exists) package.json exists=('package.json' | path exists)"
log "Installing dependencies"
let install_ec = run_and_save 0 "npm" "ci"
log $"npm ci exit: ($install_ec)"
log $"node_modules exists after install=('node_modules' | path exists)"
if ('node_modules/.bin/eslint' | path exists) { log "eslint binary found" } else { log "WARNING: eslint binary NOT found" }
log "Running ESLint"
let ec = run_and_save $install_ec "npm" "run" "lint"
log (if $ec == 0 { "OK: no lint errors" } else { "FAIL: lint errors found" })
exit $ec`,
            onError: "continue",
        },
    ],
});

const openapiCheck = new Task({
    name: "openapi-check",
    needs: [goBuild, frontendLint],
    statusReporter,
    stepTemplate: {
        env: [...goEnv, ...nodeEnv],
    },
    steps: [
        {
            name: "check-spec",
            image: goImage,
            script:
                nuHeader +
                `
log $"pwd=(pwd) uid=(id -u) go=(go version)"
log $".git exists=('.git' | path exists)"
^git config --global --add safe.directory (pwd)
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
            script:
                nuHeader +
                `
let prev_ec = (try { open --raw /tekton/home/.exit-code | str trim | into int } catch { 0 })
log $"prev exit code from check-spec: ($prev_ec)"
log $"pwd=(pwd) uid=(id -u) node=(node --version) npm=(npm --version)"
log $"node_modules exists=('node_modules' | path exists) package.json exists=('package.json' | path exists)"
log "Installing dependencies"
try { ^npm ci } catch { |e| log $"npm ci failed: ($e.msg)" }
let npm_ec = $env.LAST_EXIT_CODE
log $"npm ci exit: ($npm_ec)"
log $"node_modules exists after install=('node_modules' | path exists)"
log "Generating TypeScript types from spec"
try { ^npx openapi-typescript openapi.json -o /tmp/openapi-check.d.ts } catch { null }
let gen_ec = $env.LAST_EXIT_CODE
log $"openapi-typescript exit: ($gen_ec)"
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

// ─── Pipelines ──────────────────────────────────────────────────────────────

const allTasks = [goFmt, goTest, goBuild, openapiCheck, frontendLint];

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
    workspaceStorageSize: "5Gi",
    workspaceStorageClass: "standard-rwo",
    defaultPodSecurityContext: {
        runAsUser: 1024,
        runAsGroup: 1024,
        fsGroup: 1024,
    },
    serviceAccountAnnotations: {
        "iam.gke.io/gcp-service-account":
            "ocidex-ci-cache@default-350219.iam.gserviceaccount.com",
    },
});
