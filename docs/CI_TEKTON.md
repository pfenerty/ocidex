# Tekton CI Dev Loop

CI runs on Tekton Pipelines-as-Code. The source of truth is the TypeScript in `.tektonic/`;
`.tekton/*.yaml` is `make tekton-synth` output. Three pipelines exist: PR (gates the expensive Go
jobs on changed paths via `onChanges`), push (scoped to `main` only), and tag (multi-arch image
builds plus releases).

This document covers iterating on a pipeline change without burning an hour per attempt, and the
failure modes that have actually bitten this repo.


**Never push commits just to test a pipeline change.** Edit task YAML directly and apply it to the cluster, then create an isolated TaskRun. This turns a 1-hour iteration into ~2 minutes.

## Fast iteration on a single task

```bash
# 1. Edit the task YAML
vim .tekton/tasks/gh-release.k8s.yaml

# 2. Apply directly to the cluster — no commit, no PAC cycle
# The ocidex-ci namespace carries webhooks.knative.dev/exclude=true, which bypasses the
# Tekton admission webhook. Without it, kubectl apply fails with "non-existent variable"
# for any ${VAR#prefix} in a script (image-release-*, helm-publish, helm-release).
# The label is DECLARATIVE — do not `kubectl label` it by hand; it lives in
# homelab/talos-cluster/flux/apps/ocidex-ci/namespace.yaml and Flux reconciles it.
# Cost: the selector is `DoesNotExist`, so the label also disables Tekton's *defaulting*
# webhook for the whole namespace, PAC PipelineRuns included. Safe here because the
# tektonic-generated runs set serviceAccountName/timeouts explicitly.
kubectl apply -f .tekton/tasks/gh-release.k8s.yaml

# 3. Find a reusable workspace PVC from a recent pipeline run
kubectl get pvc -n ocidex-ci

# 4. Create an isolated TaskRun (edit params/PVC name as needed)
#    `create`, not `apply` — apply rejects generateName.
kubectl create -f - <<'EOF'
apiVersion: tekton.dev/v1
kind: TaskRun
metadata:
  generateName: test-gh-release-
  namespace: ocidex-ci
spec:
  taskRef:
    name: ocidex-gh-release
  # ALWAYS include this. tektonic stamps this exact securityContext onto every
  # PipelineRun's podTemplate, but a bare TaskRun has none — so root sidecars and
  # uid-sensitive steps pass here and fail in real CI. That gap is what let the
  # go-integration-test postgres sidecar (runAsUser: 0) ship broken: verified green
  # by ad-hoc TaskRun, then CreateContainerConfigError on every actual pipeline.
  podTemplate:
    securityContext:
      runAsUser: 1024
      runAsGroup: 1024
      fsGroup: 1024
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
    env:
      - name: HOME
        value: /tekton/home
  params:
    - name: repo-full-name
      value: pfenerty/ocidex
    - name: revision
      value: <sha>
    - name: source-branch
      value: refs/tags/v0.0.1-rc.2
  workspaces:
    - name: workspace
      persistentVolumeClaim:
        claimName: <pvc-from-recent-run>
EOF

# 5. Watch logs
kubectl logs -n ocidex-ci -l tekton.dev/taskRun=<name> -f --all-containers
```

The workspace PVC from any recent push or tag run already has the source cloned — reuse it directly. PVCs persist after the run completes until Tekton's pruning kicks in (max 5 runs per `max-keep-runs`).

## Triggering a full pipeline without a commit

Re-push the current tag to trigger the tag pipeline, or push an empty commit to trigger the push pipeline:

```bash
# Re-trigger tag pipeline (no code change needed)
git push origin :v0.0.1-rc.2 && git push origin v0.0.1-rc.2

# Trigger push pipeline — only from main; the push pipeline's trigger is
# `{ on: PUSH, branch: "main" }` (.tektonic/pipeline.ts), so a feature-branch
# push runs nothing at all.
git commit --allow-empty -m "chore: retrigger CI" && git push
```

## Watching pipeline progress

```bash
kubectl get pipelinerun -n ocidex-ci --sort-by=.metadata.creationTimestamp | tail -5
kubectl get taskrun -n ocidex-ci --sort-by=.metadata.creationTimestamp | grep <pr-name>
kubectl logs -n ocidex-ci -l tekton.dev/taskRun=<taskrun-name> -f --all-containers
```

## Known gotchas

| Symptom | Cause | Fix |
|---------|-------|-----|
| `secret-created: false` on PipelineRun | PAC GitHub App missing `Checks: read/write` | Add permission in GitHub App settings |
| `CreateContainerConfigError` on task pod | Referenced secret doesn't exist in cluster | Verify secret with `kubectl get secret -n ocidex-ci`; ensure Flux has reconciled |
| `refs/tags/v0.0.1-rc.2` appearing as image tag or release name | PAC sets `source_branch` to the full ref for tag events | Strip prefix: `TAG="${TAG#refs/tags/}"` after reading `$(params.source-branch)` |
| `403 Forbidden` pulling `ghcr.io/<other-org>/image` | Cluster's `ghcr-docker-config` only covers `pfenerty/*` | Use images from `ghcr.io/pfenerty/apko-cicd/*` or Docker Hub instead |
| Image release task shows `Succeeded` but image wasn't pushed | `onError: continue` masks step failures — TaskRun shows Succeeded even if buildctl failed | Check step logs directly; don't trust TaskRun status alone for `onError: continue` steps |
| `CreateContainerConfigError`, kubelet event `container's runAsUser breaks non-root policy` | A container sets `runAsUser: 0` but inherits pod-level `runAsNonRoot: true` from tektonic's podTemplate. The kubelet check is independent of Pod Security Admission — the namespace being PSA `privileged` does *not* exempt it | Set `runAsNonRoot: false` alongside `runAsUser: 0` on that container's `securityContext` |
| Ad-hoc TaskRun passes, same task fails in the pipeline | The TaskRun omitted `podTemplate` — no pod-level securityContext, so uid/non-root constraints never applied | Always include the `podTemplate` block from step 4 above |
| Step logs show the failure, but `report-status` logs `exit-code=0` and the TaskRun Succeeds | A nushell script body used `exit 1`. That kills the process before tektonic's `try/catch` wrapper can persist the code to `/tekton/home/.exit-code`, so it keeps its initial `0` | Raise instead: `error make {msg: "..."}`. `exit` is safe in `sh` scripts — tektonic wraps those in a subshell and reads `$?` |

## Shell variable syntax in task scripts

Tekton's admission webhook flags `$VAR` and `${VAR}` patterns in scripts as undeclared Tekton params — even when they're plain shell variables. The webhook is bypassed for the `ocidex-ci` namespace (see above), but this affects:

- **What to write**: Use `$VAR` (no braces) for simple references. For parameter expansion operators (`${VAR#prefix}`, `${VAR%suffix}`), use POSIX `sed` equivalents: `VAR=$(echo "$VAR" | sed 's|^prefix||')`.
- **`ec` and exit-code files**: Write `echo "$ec"` not `echo "${ec}"`.
- **The output line for buildctl**: Use `"name=${NAMES}"` — this is the one place where `${NAMES}` is required by buildctl's flag syntax and is exempt because it's inside a quoted arg, not a standalone variable reference.

Only the standalone `Task` object is checked. A `PipelineRun`/`TaskRun` with the same script
**embedded** as `spec.taskSpec` is admitted even without the namespace label — which is why real
CI never hit this (PAC inlines remote tasks as `taskSpec`), and why an ad-hoc TaskRun built with
an inline `taskSpec` is the escape hatch if the exclusion is ever removed.

## `.tekton/` is generated — never commit a hand-edit

`.tektonic/` is the source of truth; `.tekton/*.yaml` is `make tekton-synth` output. The
`tekton-check` PR task (`.tektonic/jobs/tekton-check/spec.ts`) re-runs synthesis in CI and **fails
the PR** if `.tekton` comes out dirty, so a hand-edit that isn't reflected in `.tektonic/` is
guaranteed red — and would be silently reverted by the next synth anyway. It is gated on
`pipelineChanged`, so it only runs when `.tektonic/**` or `.tekton/**` changed.

This does not conflict with the fast-iteration loop above: editing `.tekton/tasks/*.yaml` and
`kubectl apply`-ing it is still the right ~2-minute way to validate a task against the cluster.
Just port the change back into `.tektonic/` and re-synth before committing.

**Shell parameter expansion that cdk8s mangles** (historically `${VAR#prefix}` disappearing from
block scalars) is solved by moving the script out of the TypeScript template literal into a
sibling `.sh`/`.nu` file loaded via `.tektonic/script-lib.ts` — file contents pass through
verbatim. See `.tektonic/jobs/image-build/release.sh` (`TAG="${TAG#refs/tags/}"`, which survives
into all 11 generated `image-release-*.k8s.yaml`).

**Backticks are also unsafe** inside a `nu\`...\`` template literal — including in comments —
since they terminate the literal and produce an esbuild parse error at synth time.

**Fail with `error make {msg: "..."}`, never `exit 1`.** tektonic wraps each script body in a
try/catch that persists the caught code to `/tekton/home/.exit-code`, which the `report-status`
step reads to decide pass/fail. nushell's `exit` kills the process before that wrapper runs, so
the file keeps its initial `0` and — combined with `onError: continue` on the work step — the task
reports **green on a real failure** (ocidex-es6).
