#!/bin/sh
# Report-only SAST. On a PR, scan diff-aware (only findings the branch adds vs its base)
# via --baseline-commit; on push to main (or anything else) do a full scan. --error makes
# semgrep exit non-zero on findings so the check reflects them (pipeline stays green via
# onError: continue).
set -u

# semgrep runs git for baseline diffing; the workspace is root-owned while we run as uid
# 1024, so mark it safe (HOME=/tmp is set on the step for a writable global config).
git config --global --add safe.directory '*'

EVENT="${PAC_EVENT_TYPE:-}"
TARGET="${PAC_TARGET_BRANCH:-}"
BASELINE=""
if [ "$EVENT" = "pull_request" ] && [ -n "$TARGET" ]; then
  # Baseline = the base-branch tip. Any pre-existing finding is present at both the base
  # and HEAD, so it's excluded; only findings unique to this branch are reported. A
  # dedicated ref avoids needing $(git ...) command substitution (collides with Tekton).
  if git -c safe.directory='*' fetch --quiet origin "$TARGET" \
     && git -c safe.directory='*' update-ref refs/semgrep-baseline FETCH_HEAD; then
    BASELINE="--baseline-commit refs/semgrep-baseline"
  fi
fi

semgrep scan --error --disable-version-check --metrics off \
  --jobs 1 --max-memory 2048 \
  --config p/golang \
  --config p/typescript \
  --config p/secrets \
  $BASELINE \
  .
