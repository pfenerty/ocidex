import { onChanges } from "@tektonic-ci/core";

// Every bucket's pathspecs, keyed by its detection task's name. test/ evaluates the PR
// pipeline's gates against a changed-file set with these.
export const changePaths: Record<string, string[]> = {};

function bucket(name: string, paths: string[]) {
  changePaths[name] = paths;
  return onChanges({ name, paths });
}

// ─── File-change rules ────────────────────────────────────────────────────────
// Native tektonic `onChanges` (GitLab `rules:changes` style): each creates one
// detection task that diffs the checked-out branch against `main`
// (`git diff --name-only main...HEAD`, filtered by these git-glob pathspecs) and
// returns a `Condition` gating on a `true`/`false` result.
//
// Gating is applied ONLY on the PR pipeline (via `gated()` in pipelines.ts). On a
// PR the diff is "this branch vs main" — exactly the changed-file set we want. On
// push-to-main HEAD *is* main, so the diff would be empty (everything skipped);
// the push pipeline therefore runs ungated so the publish path always builds.
//
// Detection needs a reachable merge-base, so the PR pipeline sets
// `cloneDepth: 'full'`. On a shallow clone `onChanges` fails **open** (the gated
// job runs) rather than wrongly skipping.
//
// A gated task's detection task is wired into the pipeline by tektonic, so nothing here
// needs listing in pipelines.ts.
//
// Coarse-but-safe bucket: every Go binary imports shared `internal/` packages, so
// per-`cmd/` granularity is unsafe — any Go/Docker/db change gates the whole Go set
// on, go-build included.
// tools/ pins the linter and generators; .golangci.yml configures go-lint.
// scripts/third-party-licenses.sh runs in the Go image build (docker/Dockerfile).
export const goChanged = bucket("detect-go", [
  "**/*.go",
  "go.mod",
  "go.sum",
  "tools/**",
  ".golangci.yml",
  "docker/**",
  "db/**",
  "scripts/third-party-licenses.sh",
]);

// Frontend bucket: everything under web/ (SolidJS/TS source + package-lock.json). Gates
// frontend-lint and the web-security scan.
export const nodeChanged = bucket("detect-node", ["web/**"]);

// Union bucket (Go ∪ frontend) as a SINGLE detection task, so multi-language semgrep can
// be gated with a classic `in` guard. Deliberately NOT `or(goChanged, nodeChanged)`: that
// composes into a CEL when-expression, which needs the enable-cel-in-whenexpression Tekton
// feature flag (off on this cluster) — the same reason the rest of the pipeline avoids CEL.
export const sourceChanged = bucket("detect-source", [
  "**/*.go",
  "go.mod",
  "go.sum",
  "docker/**",
  "db/**",
  "web/**",
]);

// Pipeline-definition bucket: gates the tekton-check drift guard so it only runs when the
// pipeline sources or generated YAML change.
export const pipelineChanged = bucket("detect-pipeline", [".tektonic/**", ".tekton/**"]);

// Helm bucket: the charts themselves plus everything helm-check consumes, so editing a
// policy or the driver script re-runs the check that validates it.
export const chartsChanged = bucket("detect-charts", [
  "charts/**",
  "policy/**",
  "scripts/helm-policy-check.sh",
]);

// Codegen bucket: every generator input and output codegen-check compares (Go sources and
// the pinned generators, sqlc's queries/migrations, the OpenAPI spec, and the committed
// outputs), so hand-editing a generated file also re-runs the check that catches it.
export const codegenChanged = bucket("detect-codegen", [
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
]);
