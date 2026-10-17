import { onChanges } from "@tektonic-ci/core";

// ─── File-change rules ────────────────────────────────────────────────────────
// Native tektonic `onChanges` (GitLab `rules:changes` style): each creates one
// detection task that diffs the checked-out branch against `main`
// (`git diff --name-only main...HEAD`, filtered by these git-glob pathspecs) and
// returns a `Condition` gating on a `true`/`false` result.
//
// Gating is applied ONLY on the PR pipeline (via `gated()` in pipeline.ts). On a
// PR the diff is "this branch vs main" — exactly the changed-file set we want. On
// push-to-main HEAD *is* main, so the diff would be empty (everything skipped);
// the push pipeline therefore runs ungated so the publish path always builds.
//
// Detection needs a reachable merge-base, so the PR pipeline sets
// `cloneDepth: 'full'`. On a shallow clone `onChanges` fails **open** (the gated
// job runs) rather than wrongly skipping.
//
// A gated task's detection task is wired into the pipeline by tektonic, so nothing here
// needs listing in pipeline.ts.
//
// Coarse-but-safe bucket: every Go binary imports shared `internal/` packages, so
// per-`cmd/` granularity is unsafe — any Go/Docker/db change gates the whole Go set
// on, go-build included.
export const goChanged = onChanges({
  name: "detect-go",
  // tools/ pins the linter and generators; .golangci.yml configures go-lint.
  paths: ["**/*.go", "go.mod", "go.sum", "tools/**", ".golangci.yml", "docker/**", "db/**"],
});

// Frontend bucket: everything under web/ (SolidJS/TS source + package-lock.json). Gates
// frontend-lint and the web-security scan.
export const nodeChanged = onChanges({
  name: "detect-node",
  paths: ["web/**"],
});

// Union bucket (Go ∪ frontend) as a SINGLE detection task, so multi-language semgrep can
// be gated with a classic `in` guard. Deliberately NOT `or(goChanged, nodeChanged)`: that
// composes into a CEL when-expression, which needs the enable-cel-in-whenexpression Tekton
// feature flag (off on this cluster) — the same reason the rest of the pipeline avoids CEL.
export const sourceChanged = onChanges({
  name: "detect-source",
  paths: ["**/*.go", "go.mod", "go.sum", "docker/**", "db/**", "web/**"],
});

// Pipeline-definition bucket: gates the tekton-check drift guard so it only runs when the
// pipeline sources or generated YAML change.
export const pipelineChanged = onChanges({
  name: "detect-pipeline",
  paths: [".tektonic/**", ".tekton/**"],
});

// Helm bucket: the charts themselves plus everything helm-check consumes, so editing a
// policy or the driver script re-runs the check that validates it.
export const chartsChanged = onChanges({
  name: "detect-charts",
  paths: ["charts/**", "policy/**", "scripts/helm-policy-check.sh"],
});

// Codegen bucket: every generator input and output codegen-check compares (Go sources and
// the pinned generators, sqlc's queries/migrations, the OpenAPI spec, and the committed
// outputs), so hand-editing a generated file also re-runs the check that catches it.
export const codegenChanged = onChanges({
  name: "detect-codegen",
  paths: [
    "**/*.go",
    "go.mod",
    "go.sum",
    "tools/**",
    "db/**",
    "sqlc.yaml",
    "web/openapi.json",
    "pkg/client/.oapi-codegen.yml",
    "docs/AUTH_MATRIX.md",
    "config/operator/**",
    "charts/ocidex-operator/crds/**",
  ],
});
