import {
    Task,
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

// ─── Tasks ──────────────────────────────────────────────────────────────────

const goFmt = new Task({
    name: "go-fmt",
    params: [...statusReporter.requiredParams],
    statusContext: "ocidex/fmt",
    statusReporter,
    steps: [
        {
            name: "fmt",
            image: goImage,
            script: `#!/usr/bin/env nu
def log [msg: string] { print $"[(date now | format date '%H:%M:%S')] ($msg)" }
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
        computeResources: {
            limits: { cpu: "2", memory: "2Gi" },
            requests: { cpu: "200m", memory: "512Mi" },
        },
    },
    steps: [
        {
            name: "lint",
            image: lintImage,
            script: `#!/usr/bin/env nu
def log [msg: string] { print $"[(date now | format date '%H:%M:%S')] ($msg)" }
log "Running golangci-lint"
let result = (^golangci-lint run ./... | complete)
print $result.stdout
if ($result.stderr | str trim | str length) > 0 { print $result.stderr }
$"($result.exit_code)" | save -f /tekton/home/.exit-code
log $"Exit code: ($result.exit_code)"
exit $result.exit_code`,
            onError: "continue",
        },
    ],
});

const goTest = new Task({
    name: "go-test",
    params: [...statusReporter.requiredParams],
    needs: [goLint],
    statusContext: "ocidex/test",
    statusReporter,
    steps: [
        {
            name: "test",
            image: goImage,
            script: `#!/usr/bin/env nu
def log [msg: string] { print $"[(date now | format date '%H:%M:%S')] ($msg)" }
log "Running go test"
let result = (^go test -v -race -short ./... | complete)
print $result.stdout
if ($result.stderr | str trim | str length) > 0 { print $result.stderr }
$"($result.exit_code)" | save -f /tekton/home/.exit-code
log $"Exit code: ($result.exit_code)"
exit $result.exit_code`,
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
    steps: [
        {
            name: "build",
            image: goImage,
            script: `#!/usr/bin/env nu
def log [msg: string] { print $"[(date now | format date '%H:%M:%S')] ($msg)" }
log "Building ocidex binaries"
mut ec = 0
for cmd in ["./cmd/ocidex", "./cmd/scanner-worker", "./cmd/enrichment-worker"] {
    log $"Building ($cmd)"
    let r = (^go build -o /dev/null $cmd | complete)
    if $r.exit_code != 0 {
        print $r.stdout
        if ($r.stderr | str trim | str length) > 0 { print $r.stderr }
        $ec = $r.exit_code
    }
}
$"($ec)" | save -f /tekton/home/.exit-code
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
    statusContext: "ocidex/openapi",
    statusReporter,
    steps: [
        {
            name: "check-spec",
            image: goImage,
            script: `#!/usr/bin/env nu
def log [msg: string] { print $"[(date now | format date '%H:%M:%S')] ($msg)" }
log "Generating OpenAPI spec"
let gen = (^go run ./cmd/specgen out> /tmp/openapi-check.json | complete)
if $gen.exit_code != 0 {
    print $gen.stderr
    $"($gen.exit_code)" | save -f /tekton/home/.exit-code
    log $"FAIL: specgen exit ($gen.exit_code)"
    exit $gen.exit_code
}
log "Diffing against committed spec"
let diff = (^diff web/openapi.json /tmp/openapi-check.json | complete)
print $diff.stdout
$"($diff.exit_code)" | save -f /tekton/home/.exit-code
log (if $diff.exit_code == 0 { "OK: spec is up to date" } else { "FAIL: spec out of date" })
exit $diff.exit_code`,
            onError: "continue",
        },
        {
            name: "check-types",
            image: nodeImage,
            workingDir: "$(workspaces.workspace.path)/web",
            script: `#!/usr/bin/env nu
def log [msg: string] { print $"[(date now | format date '%H:%M:%S')] ($msg)" }
let prev_ec = (open /tekton/home/.exit-code | str trim | into int)
log "Installing node dependencies"
if not ("node_modules" | path exists) { ^npm ci --ignore-scripts }
log "Generating TypeScript types from spec"
let gen = (^npx openapi-typescript openapi.json -o /tmp/openapi-check.d.ts | complete)
if $gen.exit_code != 0 {
    print $gen.stderr
    let ec = if $prev_ec != 0 { $prev_ec } else { $gen.exit_code }
    $"($ec)" | save -f /tekton/home/.exit-code
    exit $ec
}
log "Diffing against committed types"
let diff = (^diff src/types/openapi.d.ts /tmp/openapi-check.d.ts | complete)
print $diff.stdout
let ec = if $prev_ec != 0 { $prev_ec } else { $diff.exit_code }
$"($ec)" | save -f /tekton/home/.exit-code
log (if $diff.exit_code == 0 { "OK: types up to date" } else { "FAIL: types out of date" })
exit $ec`,
            onError: "continue",
        },
    ],
});

const frontendLint = new Task({
    name: "frontend-lint",
    params: [...statusReporter.requiredParams],
    needs: [openapiCheck],
    statusContext: "ocidex/frontend-lint",
    statusReporter,
    steps: [
        {
            name: "lint",
            image: nodeImage,
            workingDir: "$(workspaces.workspace.path)/web",
            script: `#!/usr/bin/env nu
def log [msg: string] { print $"[(date now | format date '%H:%M:%S')] ($msg)" }
log "Installing node dependencies"
if not ("node_modules" | path exists) { ^npm ci }
log "Running ESLint"
let result = (^npm run lint | complete)
print $result.stdout
if ($result.stderr | str trim | str length) > 0 { print $result.stderr }
$"($result.exit_code)" | save -f /tekton/home/.exit-code
log (if $result.exit_code == 0 { "OK: no lint errors" } else { "FAIL: lint errors found" })
exit $result.exit_code`,
            onError: "continue",
        },
    ],
});

// ─── Pipelines ──────────────────────────────────────────────────────────────

const allTasks = [goFmt, goLint, goTest, goBuild, openapiCheck, frontendLint];

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
});
