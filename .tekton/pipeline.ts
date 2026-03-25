import {
    Param,
    Workspace,
    Task,
    TaskStepSpec,
    Pipeline,
    TektonProject,
    TRIGGER_EVENTS,
    RESTRICTED_STEP_SECURITY_CONTEXT,
} from "@pfenerty/tektonic";

// --- Images ─────────────────────────────────────────────────────────────────
const gitImage = "cgr.dev/chainguard/git:latest";
const curlImage = "cgr.dev/chainguard/curl:latest-dev";
const goImage = "docker.io/golang:1.25-bookworm";
const lintImage = "docker.io/golangci/golangci-lint:v2.11.4";
const nodeImage = "docker.io/node:22-bookworm";

// ─── Shared workspace ───────────────────────────────────────────────────────
const workspace = new Workspace({ name: "workspace" });

// ─── Params ─────────────────────────────────────────────────────────────────
const urlParam = new Param({ name: "url", type: "string" });
const revisionParam = new Param({ name: "revision", type: "string" });
const repoFullName = new Param({ name: "repo-full-name", type: "string" });

// ─── GitHub status helpers ──────────────────────────────────────────────────
const ghTokenEnv = {
    name: "GITHUB_TOKEN",
    valueFrom: { secretKeyRef: { name: "github-token", key: "token" } },
};

function pendingStep(context: string): TaskStepSpec {
    return {
        name: "set-pending",
        image: curlImage,
        env: [ghTokenEnv],
        command: ["sh", "-c"],
        args: [
            `curl -fsS -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -d "{\\"state\\":\\"pending\\",\\"context\\":\\"${context}\\",\\"description\\":\\"Running\\"}" \
  "https://api.github.com/repos/$(params.repo-full-name)/statuses/$(params.revision)"`,
        ],
    };
}

function statusStep(context: string): TaskStepSpec {
    return {
        name: "report-status",
        image: curlImage,
        env: [ghTokenEnv],
        command: ["sh", "-c"],
        args: [
            `EXIT_CODE=$(cat /tekton/home/.exit-code)
if [ "$EXIT_CODE" -eq 0 ]; then STATE=success DESC=Passed; else STATE=failure DESC=Failed; fi
curl -fsS -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -d "{\\"state\\":\\"$STATE\\",\\"context\\":\\"${context}\\",\\"description\\":\\"$DESC\\"}" \
  "https://api.github.com/repos/$(params.repo-full-name)/statuses/$(params.revision)"`,
        ],
    };
}

// ─── Tasks ──────────────────────────────────────────────────────────────────

const gitClone = new Task({
    name: "git-clone",
    stepTemplate: { securityContext: RESTRICTED_STEP_SECURITY_CONTEXT },
    params: [urlParam, revisionParam],
    workspaces: [workspace],
    steps: [
        {
            name: "clone",
            image: gitImage,
            workingDir: workspace.path,
            script: `#!/bin/sh
set -e
git clone -v ${urlParam} .
git config --global --add safe.directory ${workspace.path}
git checkout ${revisionParam}`,
        },
    ],
});

const goFmt = new Task({
    name: "go-fmt",
    params: [repoFullName, revisionParam],
    workspaces: [workspace],
    needs: [gitClone],
    steps: [
        pendingStep("ocidex/fmt"),
        {
            name: "fmt",
            image: goImage,
            workingDir: workspace.path,
            command: ["sh", "-c"],
            args: [
                `OUTPUT=$(gofmt -l .); EC=0; if [ -n "$OUTPUT" ]; then echo "Unformatted files:"; echo "$OUTPUT"; EC=1; fi; echo $EC > /tekton/home/.exit-code; exit $EC`,
            ],
            onError: "continue",
        },
        statusStep("ocidex/fmt"),
    ],
});

const goLint = new Task({
    name: "go-lint",
    params: [repoFullName, revisionParam],
    workspaces: [workspace],
    needs: [gitClone],
    steps: [
        pendingStep("ocidex/lint"),
        {
            name: "lint",
            image: lintImage,
            workingDir: workspace.path,
            command: ["sh", "-c"],
            args: [
                "golangci-lint run ./...; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC",
            ],
            onError: "continue",
        },
        statusStep("ocidex/lint"),
    ],
});

const goTest = new Task({
    name: "go-test",
    params: [repoFullName, revisionParam],
    workspaces: [workspace],
    needs: [gitClone],
    steps: [
        pendingStep("ocidex/test"),
        {
            name: "test",
            image: goImage,
            workingDir: workspace.path,
            command: ["sh", "-c"],
            args: [
                "go test -v -race -short ./...; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC",
            ],
            onError: "continue",
        },
        statusStep("ocidex/test"),
    ],
});

const goBuild = new Task({
    name: "go-build",
    params: [repoFullName, revisionParam],
    workspaces: [workspace],
    needs: [gitClone],
    steps: [
        pendingStep("ocidex/build"),
        {
            name: "build",
            image: goImage,
            workingDir: workspace.path,
            command: ["sh", "-c"],
            args: [
                "go build -o /dev/null ./cmd/ocidex && go build -o /dev/null ./cmd/scanner-worker && go build -o /dev/null ./cmd/enrichment-worker; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC",
            ],
            onError: "continue",
        },
        statusStep("ocidex/build"),
    ],
});

const openapiCheck = new Task({
    name: "openapi-check",
    params: [repoFullName, revisionParam],
    workspaces: [workspace],
    needs: [gitClone],
    steps: [
        pendingStep("ocidex/openapi"),
        {
            name: "check-spec",
            image: goImage,
            workingDir: workspace.path,
            command: ["sh", "-c"],
            args: [
                "go run ./cmd/specgen > /tmp/openapi-check.json && diff web/openapi.json /tmp/openapi-check.json; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC",
            ],
            onError: "continue",
        },
        {
            name: "check-types",
            image: nodeImage,
            workingDir: `${workspace.path}/web`,
            command: ["sh", "-c"],
            args: [
                `PREV_EC=$(cat /tekton/home/.exit-code); npm ci --ignore-scripts && npx openapi-typescript openapi.json -o /tmp/openapi-check.d.ts && diff src/types/openapi.d.ts /tmp/openapi-check.d.ts; EC=$?; if [ "$PREV_EC" -ne 0 ]; then EC=$PREV_EC; fi; echo $EC > /tekton/home/.exit-code; exit $EC`,
            ],
            onError: "continue",
        },
        statusStep("ocidex/openapi"),
    ],
});

const frontendLint = new Task({
    name: "frontend-lint",
    params: [repoFullName, revisionParam],
    workspaces: [workspace],
    needs: [gitClone],
    steps: [
        pendingStep("ocidex/frontend-lint"),
        {
            name: "lint",
            image: nodeImage,
            workingDir: `${workspace.path}/web`,
            command: ["sh", "-c"],
            args: [
                "npm ci && npm run lint; EC=$?; echo $EC > /tekton/home/.exit-code; exit $EC",
            ],
            onError: "continue",
        },
        statusStep("ocidex/frontend-lint"),
    ],
});

// ─── Pipelines ──────────────────────────────────────────────────────────────

const allTasks = [goFmt, goLint, goTest, goBuild, openapiCheck, frontendLint];

const pushPipeline = new Pipeline({
    name: "ocidex-push",
    triggers: [TRIGGER_EVENTS.PUSH],
    tasks: allTasks,
});

const prPipeline = new Pipeline({
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
});
