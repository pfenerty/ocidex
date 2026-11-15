#!/usr/bin/env bash
# Claude Code SessionEnd hook, vendored into each repo by `hub vendor`
# (canonical copy: pfenerty/planning vendor/beads-session-end.sh).
#
# Publishes this session's beads changes before the session goes away, so a
# session that never commits or pushes code still syncs:
#   local machine  bd-sync (Dolt over git for repos with sync.remote)
#   cloud session  bd-sync --cloud-end: pushes the rows this session changed to
#                  branch beads/inbox/<session>, since the cloud git proxy
#                  refuses refs/dolt/*. Local machines import and delete it.
#
# Never fails the session.
set -uo pipefail
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$PROJECT_DIR" 2>/dev/null || exit 0
[ -d .beads ] && [ -x .claude/hooks/bd-sync ] || exit 0
command -v bd >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 || exit 0

# The hook input on stdin is JSON carrying session_id; name the inbox after it.
if [ ! -t 0 ]; then
  sid="$(python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("session_id",""))
except Exception: pass' 2>/dev/null)"
  [ -n "$sid" ] && export CLAUDE_CODE_SESSION_ID="$sid"
fi

if [ "${CLAUDE_CODE_REMOTE:-}" = true ]; then
  .claude/hooks/bd-sync --cloud-end "$PROJECT_DIR" || true
else
  .claude/hooks/bd-sync "$PROJECT_DIR" || true
fi
exit 0
