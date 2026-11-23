import { Task, Result, equals, sh, injectedImageRef, PAC_PARAMS } from "@tektonic-ci/core";

import { sourceWs } from "./shared";

// ─── Superseded-run guard ─────────────────────────────────────────────────────
// The PAC Repository has concurrency_limit: 1 (homelab), so runs queue rather than
// overlap. That matters most for push: every image build shares one persistent buildkitd
// root, and two push runs at once fail with buildkitd unable to start. PAC can't combine
// concurrency_limit with cancel-in-progress ("cancel in progress is not supported with
// concurrency limit"), so a queued run for a commit that is no longer the branch tip
// would still do its full ~70 min of work.
//
// check-tip stands in for cancel-in-progress: it asks the remote for the tip of the
// branch this run was triggered for and records whether the run's revision is still that
// tip. Gate expensive tasks on `isTip` and a superseded run finishes in about a minute.
// The newest commit's run always comes last in the queue and always builds.
//
// Fails open: when the remote can't be reached or has no such branch (a fork PR's branch
// lives in the fork, not on origin), the result is "true" and the tasks run.

export const CHECK_TIP_TASK = "check-tip";

const tip = new Result({
  name: "tip",
  description: "'true' unless the run's revision is no longer the tip of its branch",
});

const git = "git -c safe.directory='*'";

new Task({
  name: CHECK_TIP_TASK,
  params: [PAC_PARAMS.sourceBranch, PAC_PARAMS.revision],
  results: [tip],
  workspaces: [sourceWs],
  steps: [
    {
      name: "check",
      image: injectedImageRef("sh", "git"),
      // No `$(...)` command substitution: it collides with Tekton's own interpolation.
      // PAC's source-branch is a short name on push and PR, so `refs/heads/` is prefixed
      // only when it isn't there already.
      script: sh`
        branch="${PAC_PARAMS.sourceBranch}"
        case "$branch" in refs/*) ref="$branch" ;; *) ref="refs/heads/$branch" ;; esac
        printf true > ${tip.path}
        if ${git} ls-remote origin "$ref" > /tmp/tektonic-tip.txt 2>/dev/null; then
          if [ -s /tmp/tektonic-tip.txt ]; then
            if ! grep -q "^${PAC_PARAMS.revision}" /tmp/tektonic-tip.txt; then
              echo "superseded: ${PAC_PARAMS.revision} is no longer the tip of $ref; skipping"
              cat /tmp/tektonic-tip.txt
              printf false > ${tip.path}
            fi
          fi
        fi`,
    },
  ],
});

// Bound to the check-tip task, so a task gated on it gains check-tip in its `needs`.
export const isTip = equals(tip, "true");
