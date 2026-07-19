#!/bin/sh
# Report-only secrets scan in git mode (scans tracked commits, so build/dep caches
# on the shared workspace are never scanned). Scope is situational via PAC context
# injected as env (podTemplateEnv): a PR scans only the commits it adds vs its base
# branch; a push to main scans the full history. Fails safe to a full scan if the
# event/base is unknown or the base can't be fetched. gitleaks exits non-zero on a
# leak, which the statusReporter surfaces as a failed check (pipeline stays green
# via onError: continue).
set -u
CFG="--config .gitleaks.toml"
COMMON="--redact --verbose --no-banner"
EVENT="${PAC_EVENT_TYPE:-}"
TARGET="${PAC_TARGET_BRANCH:-}"

if [ "$EVENT" = "pull_request" ] && [ -n "$TARGET" ]; then
  BASE="$TARGET"
else
  BASE=""
fi

if [ -n "$BASE" ]; then
  git -c safe.directory='*' fetch --quiet origin "$BASE" || BASE=""
fi

if [ -n "$BASE" ]; then
  # Only the commits this branch adds on top of the base.
  gitleaks git . $CFG $COMMON --log-opts="FETCH_HEAD..HEAD"
else
  # Full history.
  gitleaks git . $CFG $COMMON
fi
