import {
  Task,
  TaskVolumeSpec,
  Workspace,
  GitPipeline,
  PACProject,
  TRIGGER_EVENTS,
  GitHubStatusReporter,
  nu,
  sh,
  scriptFromFile,
  ScriptInput,
} from "@pfenerty/tektonic";

// --- Images ─────────────────────────────────────────────────────────────────
const goImage = "ghcr.io/pfenerty/apko-cicd/golang:1.26";
const lintImage = "ghcr.io/pfenerty/apko-cicd/golangci-lint:2.12.2-go1.26";
const nodeImage = "ghcr.io/pfenerty/apko-cicd/nodejs:22";

// ─── Status reporter ─────────────────────────────────────────────────────────
const statusReporter = new GitHubStatusReporter({
  tokenSecretName: "github-pipeline-token",
  // 5 tasks report status → 5 steps in set-status-pending, each just an HTTP POST.
  // Default 512Mi limit per step causes OOM on constrained nodes; these are tight
  // but sufficient for nushell + a single GitHub API call.
  pendingTaskComputeResources: {
    requests: { cpu: "25m", memory: "64Mi" },
    limits: { cpu: "200m", memory: "128Mi" },
  },
});

// ─── Cache workspaces (PVC-backed, local-path) ───────────────────────────────
// Persistent PVCs provisioned once; mounted read-write by each pipeline run.
// ReadWriteOnce is required — local-path does not support ReadWriteMany.
// Concurrent pipeline runs on the same node can both mount the PVC but risk
// cache corruption on simultaneous saves (non-fatal: next run rebuilds).
const goCacheWs = new Workspace({ name: "go-cache" });
const nodeCacheWs = new Workspace({ name: "node-cache" });

const goCache = {
  name: "go-cache",
  key: ["go.sum"],
  // Use dotdir paths so `go test ./...` skips them (Go ignores dirs starting with '.')
  paths: [".go-mod", ".go-build"],
  workspace: goCacheWs,
  compress: true,
  workingDir: "$(workspaces.workspace.path)",
};

const nodeModulesCache = {
  name: "node-modules",
  key: ["package-lock.json"],
  paths: ["node_modules"],
  workspace: nodeCacheWs,
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

// ─── Tasks ──────────────────────────────────────────────────────────────────
// All status-reporting tasks use the tektonic script API (`nu`/`sh`): the
// plugin supplies the shebang + `log` helper, and synth injects exit-code
// capture and onError:'continue' (because a statusReporter is set). Bodies
// therefore just run commands and signal failure by raising / a non-zero
// external command — no nuHeader, run_and_save, or manual /tekton/home/.exit-code.
const goFmt = new Task({
  name: "go-fmt",
  statusReporter,
  steps: [
    {
      name: "fmt",
      image: goImage,
      // Migrated to the tektonic script API: `nu` supplies the shebang + `log`
      // helper, and synth injects exit-code capture + onError:'continue' because
      // a statusReporter is set — so no nuHeader/run_and_save/manual exit-code.
      script: nu`
        log "Checking gofmt"
        let unformatted = (^gofmt -l . | complete | get stdout | str trim)
        if ($unformatted | str length) > 0 {
          print "Unformatted files:"; print $unformatted
          error make {msg: "gofmt: formatting issues found"}
        }
        log "OK: all files formatted"
      `,
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
        limits: { cpu: "2", memory: "2Gi", "ephemeral-storage": "4Gi" },
        requests: {
          cpu: "500m",
          memory: "1Gi",
          "ephemeral-storage": "2Gi",
        },
      },
      script: nu`
        log $"pwd=(pwd) uid=(id -u) go=(go version)"
        log $"GOMODCACHE=($env.GOMODCACHE) GOCACHE=($env.GOCACHE)"
        log $".git exists=('.git' | path exists) go-mod exists=('go-mod' | path exists)"
        ^git config --global --add safe.directory (pwd)
        log $"git rev-parse HEAD: (^git rev-parse --short HEAD)"
        log "Building ocidex binaries"
        for cmd in ["./cmd/ocidex", "./cmd/scanner-worker", "./cmd/enrichment-worker"] {
          log $"Building ($cmd)"
          ^go build -o /dev/null $cmd
        }
        log "OK: all binaries built"
      `,
      onError: "continue",
    },
  ],
});

const goTest = new Task({
  name: "go-test",
  needs: [goBuild],
  caches: [goCache],
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
      script: nu`
        log "Running go test"
        ^go test -v -short -p 2 ./...
        log "OK: tests passed"
      `,
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
        requests: { cpu: "500m", memory: "2Gi" },
      },
      script: nu`
        log $"pwd=(pwd) uid=(id -u) node=(node --version) npm=(npm --version)"
        log $"node_modules exists=('node_modules' | path exists) package.json exists=('package.json' | path exists)"
        log "Installing dependencies"
        ^npm ci
        log $"node_modules exists after install=('node_modules' | path exists)"
        if ('node_modules/.bin/eslint' | path exists) { log "eslint binary found" } else { log "WARNING: eslint binary NOT found" }
        log "Running ESLint"
        ^npm run lint
        log "OK: no lint errors"
      `,
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
      script: nu`
        log $"pwd=(pwd) uid=(id -u) go=(go version)"
        log $".git exists=('.git' | path exists)"
        ^git config --global --add safe.directory (pwd)
        log "Generating OpenAPI spec"
        ^go run ./cmd/specgen out> /tmp/openapi-check.json
        log "Diffing against committed spec"
        ^diff web/openapi.json /tmp/openapi-check.json
        log "OK: spec is up to date"
      `,
      onError: "continue",
    },
    {
      name: "check-types",
      image: nodeImage,
      workingDir: "$(workspaces.workspace.path)/web",
      computeResources: {
        limits: { cpu: "2", memory: "3Gi" },
        requests: { cpu: "100m", memory: "2Gi" },
      },
      // No manual prev-exit-code handling: synth's exit-code contract keeps the
      // worst code across both steps of this task automatically, so a check-spec
      // failure already propagates to the reporter even if check-types passes.
      script: nu`
        log $"pwd=(pwd) uid=(id -u) node=(node --version) npm=(npm --version)"
        log $"node_modules exists=('node_modules' | path exists) package.json exists=('package.json' | path exists)"
        log "Installing dependencies"
        ^npm ci
        log $"node_modules exists after install=('node_modules' | path exists)"
        log "Generating TypeScript types from spec"
        ^npx openapi-typescript openapi.json -o /tmp/openapi-check.d.ts
        log "Diffing against committed types"
        ^diff src/types/openapi.d.ts /tmp/openapi-check.d.ts
        log "OK: types up to date"
      `,
      onError: "continue",
    },
  ],
});

// ─── BuildKit image build tasks ──────────────────────────────────────────────
const dockerConfigVolume: TaskVolumeSpec = {
  name: "docker-config",
  secret: { secretName: "ghcr-docker-config" },
};

// Shared Task skeleton — only the script differs between push and release builds.
function buildImageTask(taskName: string, script: ScriptInput): Task {
  return new Task({
    name: taskName,
    statusReporter,
    needs: [goTest, openapiCheck],
    volumes: [dockerConfigVolume],
    steps: [
      {
        name: "build-and-push",
        image: "moby/buildkit:rootless",
        securityContext: {
          seccompProfile: { type: "Unconfined" },
          allowPrivilegeEscalation: true,
          runAsUser: 1000,
          runAsGroup: 1000,
          capabilities: { drop: [], add: ["SETUID", "SETGID"] },
        },
        workingDir: "$(workspaces.workspace.path)",
        computeResources: {
          requests: { cpu: "500m", memory: "1Gi" },
          limits: { cpu: "4", memory: "4Gi" },
        },
        env: [
          { name: "DOCKER_CONFIG", value: "/tmp/docker-auth" },
          {
            name: "BUILDKITD_FLAGS",
            value:
              "--oci-worker-snapshotter=native --oci-worker-no-process-sandbox",
          },
        ],
        volumeMounts: [
          {
            name: "docker-config",
            mountPath: "/tmp/docker-auth/config.json",
            subPath: ".dockerconfigjson",
            readOnly: true,
          },
        ],
        onError: "continue",
        script,
      },
    ],
  });
}

// Push pipeline: tags images as sha-<short> and main.
function imageBuildTask(
  name: string,
  dockerfile: string,
  target?: string,
): Task {
  const image = `ghcr.io/pfenerty/ocidex-${name}`;
  const targetOpt = target ? `  --opt target=${target} \\\n` : "";
  // Migrated to sh`` (POSIX): the moby/buildkit image ships /bin/sh, not bash.
  // tektonic synth supplies the shebang + exit-code capture, so the manual
  // ec=$?/echo/exit tail is gone. Shell vars use \${...} to avoid JS interpolation.
  return buildImageTask(
    `image-build-${name}`,
    sh`
SHORT_SHA=$(echo "$(params.revision)" | cut -c1-8)
VERSION="main-\${SHORT_SHA}"

buildctl-daemonless.sh build \\
  --frontend dockerfile.v0 \\
  --local context=. \\
  --local dockerfile=. \\
  --opt filename=${dockerfile} \\
${targetOpt}  --opt platform=linux/amd64,linux/arm64 \\
  --opt build-arg:VERSION="\${VERSION}" \\
  --opt build-arg:COMMIT="$(params.revision)" \\
  --opt build-arg:DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \\
  --opt attest:provenance=mode=max \\
  --opt attest:sbom= \\
  --output "type=image,\\"name=${image}:sha-\${SHORT_SHA},${image}:main\\",push=true,attestation-manifest-referrers=true"
`,
  );
}

// Release pipeline: tags images with semver aliases from the git tag name.
// latest is only added for stable releases (no hyphen in tag).
function imageBuildTagTask(
  name: string,
  dockerfile: string,
  target?: string,
): Task {
  const image = `ghcr.io/pfenerty/ocidex-${name}`;
  const targetOpt = target ? `  --opt target=${target} \\\n` : "";
  return buildImageTask(
    `image-release-${name}`,
    `#!/bin/sh
TAG="$(params.source-branch)"
TAG="\${TAG#refs/tags/}"
BARE="\${TAG#v}"
MAJOR="$(echo "\${BARE}" | cut -d. -f1)"
MINOR="$(echo "\${BARE}" | cut -d. -f2)"

NAMES="${image}:\${TAG},${image}:\${MAJOR}.\${MINOR},${image}:\${MAJOR}"
if ! echo "\${TAG}" | grep -q '-'; then
  NAMES="\${NAMES},${image}:latest"
fi

buildctl-daemonless.sh build \\
  --frontend dockerfile.v0 \\
  --local context=. \\
  --local dockerfile=. \\
  --opt filename=${dockerfile} \\
${targetOpt}  --opt platform=linux/amd64,linux/arm64 \\
  --opt build-arg:VERSION="\${TAG}" \\
  --opt build-arg:COMMIT="$(params.revision)" \\
  --opt build-arg:DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \\
  --opt attest:provenance=mode=max \\
  --opt attest:sbom= \\
  --output "type=image,\\"name=\${NAMES}\\",push=true,attestation-manifest-referrers=true"
ec=$?
echo "\${ec}" > /tekton/home/.exit-code
exit "\${ec}"
`,
  );
}

const imageBuilds = [
  imageBuildTask("api", "docker/Dockerfile", "api"),
  imageBuildTask("scanner-worker", "docker/Dockerfile", "scanner-worker"),
  imageBuildTask("enrichment-worker", "docker/Dockerfile", "enrichment-worker"),
  imageBuildTask("web", "docker/web/Dockerfile"),
  imageBuildTask("operator", "docker/Dockerfile", "operator"),
];

const imageBuildsTag = [
  imageBuildTagTask("api", "docker/Dockerfile", "api"),
  imageBuildTagTask("scanner-worker", "docker/Dockerfile", "scanner-worker"),
  imageBuildTagTask("enrichment-worker", "docker/Dockerfile", "enrichment-worker"),
  imageBuildTagTask("web", "docker/web/Dockerfile"),
  imageBuildTagTask("operator", "docker/Dockerfile", "operator"),
];

const helmPublish = new Task({
  name: "helm-publish",
  statusReporter,
  needs: [...imageBuilds],
  volumes: [dockerConfigVolume],
  steps: [
    {
      name: "package-and-push",
      image: "alpine/helm:3",
      workingDir: "$(workspaces.workspace.path)",
      onError: "continue",
      env: [{ name: "DOCKER_CONFIG", value: "/tmp/helm-auth" }],
      volumeMounts: [
        {
          name: "docker-config",
          mountPath: "/tmp/helm-auth/config.json",
          subPath: ".dockerconfigjson",
          readOnly: true,
        },
      ],
      // File-based authoring: the script lives in scripts/helm-publish.sh
      // (shellcheck-able, no JS-template escaping). tektonic inlines it and
      // injects exit-code capture; manual ec=$?/exit plumbing is gone.
      script: scriptFromFile("scripts/helm-publish.sh"),
    },
  ],
});

const helmRelease = new Task({
  name: "helm-release",
  statusReporter,
  needs: [...imageBuildsTag],
  volumes: [dockerConfigVolume],
  steps: [
    {
      name: "package-and-push",
      image: "alpine/helm:3",
      workingDir: "$(workspaces.workspace.path)",
      onError: "continue",
      env: [{ name: "DOCKER_CONFIG", value: "/tmp/helm-auth" }],
      volumeMounts: [
        {
          name: "docker-config",
          mountPath: "/tmp/helm-auth/config.json",
          subPath: ".dockerconfigjson",
          readOnly: true,
        },
      ],
      // sh`` + `set -e`: fail-fast on the first failing helm command; synth
      // captures the exit code, so the manual ec=$?/.exit-code plumbing is gone.
      script: sh`
        set -e
        TAG="$(params.source-branch)"
        TAG="\${TAG#refs/tags/}"
        VERSION="\${TAG#v}"

        helm package charts/ocidex --version "\${VERSION}" --app-version "\${TAG}"
        helm package charts/ocidex-operator --version "\${VERSION}" --app-version "\${TAG}"
        helm push "ocidex-\${VERSION}.tgz" oci://ghcr.io/pfenerty/charts
        helm push "ocidex-operator-\${VERSION}.tgz" oci://ghcr.io/pfenerty/charts
      `,
    },
  ],
});

const ghRelease = new Task({
  name: "gh-release",
  statusReporter,
  needs: [...imageBuildsTag],
  steps: [
    {
      name: "create-release",
      image: "ghcr.io/pfenerty/apko-cicd/base:stable",
      workingDir: "$(workspaces.workspace.path)",
      onError: "continue",
      env: [
        {
          name: "GH_TOKEN",
          valueFrom: { secretKeyRef: { name: "github-pipeline-token", key: "token" } },
        },
      ],
      // nu`` supplies the shebang + log helper; a failing `http post` raises and
      // synth captures it as the failure code — no try/catch + manual exit-code.
      script: nu`
        let tag = ("$(params.source-branch)" | str replace "refs/tags/" "")
        let is_prerelease = ($tag | str contains "-")
        let body_text = try { open --raw "CHANGELOG.md" } catch { "" }

        log $"creating release ($tag) prerelease=($is_prerelease)"

        let url = $"https://api.github.com/repos/$(params.repo-full-name)/releases"
        let payload = { tag_name: $tag, name: $tag, body: $body_text, prerelease: $is_prerelease, draft: false }

        http post $url $payload -t application/json -H [
          Authorization $"token ($env.GH_TOKEN)"
          Accept "application/vnd.github+json"
          X-GitHub-Api-Version "2022-11-28"
        ]
        log "release created"
      `,
    },
  ],
});

// ─── Pipelines ──────────────────────────────────────────────────────────────

const allTasks = [goFmt, goTest, goBuild, openapiCheck, frontendLint];

const pushPipeline = new GitPipeline({
  name: "ocidex-push",
  triggers: [TRIGGER_EVENTS.PUSH],
  tasks: [...allTasks, ...imageBuilds, helmPublish],
});

const prPipeline = new GitPipeline({
  name: "ocidex-pull-request",
  triggers: [TRIGGER_EVENTS.PULL_REQUEST],
  tasks: allTasks,
});

const tagPipeline = new GitPipeline({
  name: "ocidex-tag",
  triggers: [TRIGGER_EVENTS.TAG],
  tasks: [...imageBuildsTag, helmRelease, ghRelease],
});

// ─── Synthesize ─────────────────────────────────────────────────────────────
new PACProject({
  name: "ocidex",
  namespace: "ocidex-ci",
  pipelines: [pushPipeline, prPipeline, tagPipeline],
  outdir: "../.tekton",
  repoRelativePath: ".tekton",
  serviceAccountName: "default",
  workspaceStorageSize: "5Gi",
  workspaceStorageClass: "local-path",
  defaultPodSecurityContext: {
    runAsUser: 1024,
    runAsGroup: 1024,
    fsGroup: 1024,
  },
  caches: [
    {
      workspace: goCacheWs,
      storageSize: "5Gi",
      storageClassName: "local-path",
    },
    {
      workspace: nodeCacheWs,
      storageSize: "2Gi",
      storageClassName: "local-path",
    },
  ],
});
