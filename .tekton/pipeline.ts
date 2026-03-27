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
// Go module + build cache keyed on go.sum, stored at filesystem root-relative paths
const goCache: TaskCacheSpec = {
    key: ["$(workspaces.workspace.path)/go.sum"],
    paths: ["go/pkg/mod", "root/.cache/go-build"],
    workspace: goCacheWs,
    compress: true,
    workingDir: "/",
};

// npm cache keyed on web/package-lock.json; caching ~/.npm speeds up npm ci
const nodeCache: TaskCacheSpec = {
    key: ["$(workspaces.workspace.path)/web/package-lock.json"],
    paths: ["root/.npm"],
    workspace: nodeCacheWs,
    compress: true,
    workingDir: "/",
};

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
    statusContext: "ocidex/lint",
    statusReporter,
    caches: [goCache],
    steps: [
        {
            name: "lint",
            image: lintImage,
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
    statusContext: "ocidex/test",
    statusReporter,
    caches: [goCache],
    steps: [
        {
            name: "test",
            image: goImage,
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
    statusContext: "ocidex/build",
    statusReporter,
    caches: [goCache],
    steps: [
        {
            name: "build",
            image: goImage,
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
    statusContext: "ocidex/openapi",
    statusReporter,
    caches: [goCache, nodeCache],
    steps: [
        {
            name: "check-spec",
            image: goImage,
            command: ["sh", "-c"],
            args: [
                "go run ./cmd/specgen > /tmp/openapi-check.json && diff web/openapi.json /tmp/openapi-check.json; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC",
            ],
            onError: "continue",
        },
        {
            name: "check-types",
            image: nodeImage,
            workingDir: "$(workspaces.workspace.path)/web",
            command: ["sh", "-c"],
            args: [
                `PREV_EC=$(cat /tekton/home/.exit-code); npm ci --ignore-scripts && npx openapi-typescript openapi.json -o /tmp/openapi-check.d.ts && diff src/types/openapi.d.ts /tmp/openapi-check.d.ts; EC=$?; if [ "$PREV_EC" -ne 0 ]; then EC=$PREV_EC; fi; echo $EC > /tekton/home/.exit-code; exit $EC`,
            ],
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
    caches: [nodeCache],
    steps: [
        {
            name: "lint",
            image: nodeImage,
            workingDir: "$(workspaces.workspace.path)/web",
            command: ["sh", "-c"],
            args: [
                "npm ci && npm run lint; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC",
            ],
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
    caches: [
        { workspace: goCacheWs, storageSize: "5Gi" },
        { workspace: nodeCacheWs, storageSize: "2Gi" },
    ],
});
