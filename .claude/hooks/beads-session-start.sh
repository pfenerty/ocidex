#!/usr/bin/env bash
# Beads SessionStart hook, vendored into each repo's .claude/hooks/ by
# `~/code/common/bin/hub vendor`. Edit the copy in pfenerty/planning
# (vendor/beads-session-start.sh), not the vendored one.
#
# Written for Claude Code on the web, where the container is a cold clone: no
# Flox, no bd, no Dolt database (.beads/embeddeddolt/ is gitignored, so issue
# state arrives only as the committed .beads/issues.jsonl), no global git hooks
# and no beads merge driver. Locally, Flox supplies bd and the global git setup
# from ~/code/common applies, so this reduces to a guarded import plus bd prime.
#
# Idempotent, non-interactive, never fails the session.
set -uo pipefail

# Pinned to the bd version in pfenerty/planning's Flox manifest (rewritten by
# `hub vendor`). @latest would let cloud and local bd disagree on the JSONL.
BD_VERSION="v1.0.3"

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
HOOKS_DIR="$PROJECT_DIR/.claude/hooks"
cd "$PROJECT_DIR" || exit 0
[ -d .beads ] || exit 0

note() { echo "[beads-session-start] $*" >&2; }

# ── bd ───────────────────────────────────────────────────────────────────────
# The Go module path is still github.com/steveyegge/beads. CGO plus the
# gms_pure_go tag make the binary embedded-Dolt capable. There are no prebuilt
# release assets, so `go install` is the only path.
GOBIN_DIR="$(go env GOBIN 2>/dev/null || true)"
[ -n "$GOBIN_DIR" ] || GOBIN_DIR="$(go env GOPATH 2>/dev/null)/bin"

if ! command -v bd >/dev/null 2>&1 && [ -x "$GOBIN_DIR/bd" ]; then
  export PATH="$PATH:$GOBIN_DIR"
fi

if ! command -v bd >/dev/null 2>&1; then
  if command -v go >/dev/null 2>&1; then
    note "installing bd $BD_VERSION (go install, a few minutes on a cold container)..."
    if CGO_ENABLED=1 GOFLAGS="${GOFLAGS:+$GOFLAGS }-tags=gms_pure_go" \
         go install "github.com/steveyegge/beads/cmd/bd@$BD_VERSION" 2>&1 | tail -3 >&2; then
      export PATH="$PATH:$GOBIN_DIR"
      note "bd installed to $GOBIN_DIR/bd"
    else
      note "bd install failed; issue tracking unavailable this session"
    fi
  else
    note "go not available; skipping bd install"
  fi
fi

command -v bd >/dev/null 2>&1 || exit 0
if [ -n "${CLAUDE_ENV_FILE:-}" ] && [ -x "$GOBIN_DIR/bd" ]; then
  echo "export PATH=\"\$PATH:$GOBIN_DIR\"" >> "$CLAUDE_ENV_FILE"
fi

# ── Beads database ───────────────────────────────────────────────────────────
# Fresh clone: rebuild the DB from the committed JSONL. Existing DB (a local
# checkout, or a reused container snapshot): import only rows that are newer in
# the file. Plain `bd import` would overwrite newer local rows.
chmod 700 .beads 2>/dev/null || true
if [ ! -d .beads/embeddeddolt ] && [ ! -d .beads/dolt ]; then
  prefix="$(sed -n 's/^issue-prefix:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' .beads/config.yaml 2>/dev/null | head -1)"
  if [ -z "$prefix" ] && [ -s .beads/issues.jsonl ]; then
    # IDs look like <prefix>-<hash>[.<n>]; the prefix itself may contain dashes.
    prefix="$(grep -m1 -o '"id":"[^"]*"' .beads/issues.jsonl | sed 's/"id":"\(.*\)-[^-]*"/\1/')"
  fi
  if [ -z "$prefix" ]; then
    note "cannot determine the issue prefix; skipping database rebuild"
  else
    note "no local beads database; rebuilding from .beads/issues.jsonl (prefix $prefix)"
    head_before="$(git rev-parse HEAD 2>/dev/null || true)"
    dirty_before="$(git status --porcelain 2>/dev/null)"
    # --skip-agents/--skip-hooks stop bd init rewriting CLAUDE.md, AGENTS.md,
    # .claude/settings.json and the git hooks; --from-jsonl hydrates in one step.
    # (No --init-if-missing: bd 1.0.3 lacks it, and the DB-absent guard covers it.)
    if bd init --prefix "$prefix" --skip-agents --skip-hooks --from-jsonl \
               --non-interactive --quiet >/dev/null 2>&1; then
      note "beads database rebuilt from $(wc -l < .beads/issues.jsonl | tr -d ' ') rows"
    else
      note "bd init failed; issue tracking unavailable this session"
    fi
    # bd init commits and rewrites tracked files even with the --skip flags.
    # Undo its commit, and restore only the files that it (not the developer)
    # dirtied.
    if [ -n "$head_before" ] && [ "$head_before" != "$(git rev-parse HEAD 2>/dev/null)" ] \
       && git log -1 --pretty=%s 2>/dev/null | grep -q '^bd init'; then
      git reset --mixed "$head_before" >/dev/null 2>&1 || true
      note "reverted the commit bd init made"
    fi
    git status --porcelain 2>/dev/null | while IFS= read -r line; do
      printf '%s\n' "$dirty_before" | grep -qxF "$line" && continue
      path="${line:3}"
      if git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
        git checkout -- "$path" >/dev/null 2>&1 || true
      fi
    done
  fi
elif [ -x "$HOOKS_DIR/bd-import-newer" ] && command -v python3 >/dev/null 2>&1; then
  "$HOOKS_DIR/bd-import-newer" "$PROJECT_DIR" || true
fi

# ── Merge driver ─────────────────────────────────────────────────────────────
# .gitattributes routes .beads/issues.jsonl to merge=beads. Locally that driver
# is configured globally; in a container nothing defines it and git falls back
# to a line merge, which is how stale branches have reverted closures before.
if [ -z "$(git config merge.beads.driver 2>/dev/null)" ] && [ -x "$HOOKS_DIR/bd-jsonl-merge" ] \
   && command -v python3 >/dev/null 2>&1; then
  git config merge.beads.name "beads JSONL merge"
  git config merge.beads.driver "\"$HOOKS_DIR/bd-jsonl-merge\" %O %A %B"
fi
# filter=beads sorts memory rows, which bd 1.0.3 exports in random order, so a
# reshuffle doesn't show up as a change.
if [ -z "$(git config filter.beads.clean 2>/dev/null)" ] && [ -x "$HOOKS_DIR/bd-jsonl-clean" ] \
   && command -v python3 >/dev/null 2>&1; then
  git config filter.beads.clean "\"$HOOKS_DIR/bd-jsonl-clean\""
fi

# ── Issue-tracker context ────────────────────────────────────────────────────
# stdout becomes session context.
bd prime 2>/dev/null || true
exit 0
