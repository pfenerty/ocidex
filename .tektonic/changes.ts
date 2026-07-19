import { onChanges } from "@pfenerty/tektonic";

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
// Coarse-but-safe bucket: every Go binary imports shared `internal/` packages, so
// per-`cmd/` granularity is unsafe — any Go/Docker/db change gates the whole Go set
// on. Frontend-lint is a dependency of openapi-check (node_modules warmup), so it
// can't be gated independently and runs on every PR; a dedicated `web` bucket would
// only pay off once that coupling is broken, so it's omitted for now.
export const goChanged = onChanges({
  name: "detect-go",
  paths: ["**/*.go", "go.mod", "go.sum", "docker/**", "db/**"],
});

// The detection task backing the condition above. `gated()` overrides only the
// emitted pipeline-task `when` and does not auto-wire the producing task into the
// pipeline, so it must be listed explicitly on the PR pipeline. Tekton orders
// consumers after it automatically via the `$(tasks.detect-go.results.changed)`
// result reference in the `when` clauses.
export const detectTasks = [...goChanged.sources()];
