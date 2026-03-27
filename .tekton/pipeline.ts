import {
    Param,
    Workspace,
    Task,
    TaskCacheSpec,
    GitPipeline,
    TektonProject,
    TRIGGER_EVENTS,
    GitHubStatusReporter,
} from "@pfenerty/tektonic";

// --- Images ─────────────────────────────────────────────────────────────────
const goImage = "docker.io/golang:1.25-bookworm";
const lintImage = "docker.io/golangci/golangci-lint:v2.11.4";
const nodeImage = "docker.io/node:22-bookworm";

// ─── Status reporter ─────────────────────────────────────────────────────────
const statusReporter = new GitHubStatusReporter();

// ─── Cache workspaces ────────────────────────────────────────────────────────
const goCacheWs = new Workspace({ name: "go-cache" });
const nodeCacheWs = new Workspace({ name: "node-cache" });

// ─── Cache specs ─────────────────────────────────────────────────────────────
// node_modules is cached by content-hashing web/package-lock.json.
// The restore step unpacks node_modules into the workspace; the step then skips
// `npm ci` if node_modules already exists (cache hit).
const nodeModulesCache: TaskCacheSpec = {
    key: ["web/package-lock.json"],
    paths: ["web/node_modules"],
    workspace: nodeCacheWs,
    image: nodeImage,
    compress: true,
    workingDir: "$(workspaces.workspace.path)",
};

// ─── Go env helpers ──────────────────────────────────────────────────────────
// Point all Go toolchain caches directly at the go-cache PVC mount.
// The NFS PVC is writable by uid 1024 (all_squash anonuid=1024), so no
// tar restore/save steps are needed — the PVC IS the persistent cache.
const goEnv = [
    { name: "GOPATH", value: "$(workspaces.go-cache.path)" },
    { name: "GOCACHE", value: "$(workspaces.go-cache.path)/.go-build-cache" },
];

const lintEnv = [
    ...goEnv,
    { name: "GOLANGCI_LINT_CACHE", value: "$(workspaces.go-cache.path)/.golangci-cache" },
];

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
            command: ["sh", "-c"],
            args: [
                `OUTPUT=$(gofmt -l .); EC=0; if [ -n "$OUTPUT" ]; then echo "Unformatted files:"; echo "$OUTPUT"; EC=1; fi; echo $EC > /tekton/home/.exit-code; exit $EC`,
            ],
            onError: "continue",
        },
    ],
});

const goLint = new Task({
    name: "go-lint",
    params: [...statusReporter.requiredParams],
    needs: [goFmt],
    workspaces: [goCacheWs],
    statusContext: "ocidex/lint",
    statusReporter,
    steps: [
        {
            name: "lint",
            image: lintImage,
            env: lintEnv,
            command: ["sh", "-c"],
            args: [
                "golangci-lint run ./...; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC",
            ],
            onError: "continue",
        },
    ],
});

const goTest = new Task({
    name: "go-test",
    params: [...statusReporter.requiredParams],
    needs: [goLint],
    workspaces: [goCacheWs],
    statusContext: "ocidex/test",
    statusReporter,
    steps: [
        {
            name: "test",
            image: goImage,
            env: goEnv,
            command: ["sh", "-c"],
            args: [
                "go test -v -race -short ./...; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC",
            ],
            onError: "continue",
        },
    ],
});

const goBuild = new Task({
    name: "go-build",
    params: [...statusReporter.requiredParams],
    needs: [goTest],
    workspaces: [goCacheWs],
    statusContext: "ocidex/build",
    statusReporter,
    steps: [
        {
            name: "build",
            image: goImage,
            env: goEnv,
            command: ["sh", "-c"],
            args: [
                "go build -o /dev/null ./cmd/ocidex && go build -o /dev/null ./cmd/scanner-worker && go build -o /dev/null ./cmd/enrichment-worker; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC",
            ],
            onError: "continue",
        },
    ],
});

const openapiCheck = new Task({
    name: "openapi-check",
    params: [...statusReporter.requiredParams],
    needs: [goTest],
    workspaces: [goCacheWs],
    statusContext: "ocidex/openapi",
    statusReporter,
    caches: [nodeModulesCache],
    steps: [
        {
            name: "check-spec",
            image: goImage,
            env: goEnv,
            command: ["sh", "-c"],
            args: [
                "go run ./cmd/specgen > /tmp/openapi-check.json && diff web/openapi.json /tmp/openapi-check.json; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC",
            ],
            onError: "continue",
        },
        {
            name: "check-types",
            image: nodeImage,
            env: [{ name: "npm_config_cache", value: nodeCacheWs.path }],
            workingDir: "$(workspaces.workspace.path)/web",
            script: `#!/bin/sh
PREV_EC=$(cat /tekton/home/.exit-code)
[ ! -d node_modules ] && npm ci --ignore-scripts
npx openapi-typescript openapi.json -o /tmp/openapi-check.d.ts && diff src/types/openapi.d.ts /tmp/openapi-check.d.ts
EC=$?; if [ "$PREV_EC" -ne 0 ]; then EC=$PREV_EC; fi; echo $EC > /tekton/home/.exit-code; exit $EC`,
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
    caches: [nodeModulesCache],
    steps: [
        {
            name: "lint",
            image: nodeImage,
            env: [{ name: "npm_config_cache", value: nodeCacheWs.path }],
            workingDir: "$(workspaces.workspace.path)/web",
            script: `#!/bin/sh
[ ! -d node_modules ] && npm ci
npm run lint; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC`,
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
    // The nfs-client storage class uses all_squash (anonuid=1024), which maps every
    // client UID/GID to 1024 on the NFS server. Running pods as 1024 ensures the
    // process UID matches the file owner UID, granting write access to PVC-backed
    // cache directories.
    defaultPodSecurityContext: {
        runAsUser: 1024,
        runAsGroup: 1024,
        fsGroup: 1024,
    },
    caches: [
        { workspace: goCacheWs, storageSize: "5Gi" },
        { workspace: nodeCacheWs, storageSize: "2Gi" },
    ],
});
