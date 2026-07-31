---
description: Autonomously plan and implement every ready story in a beads epic, one after another, stopping only when the epic is exhausted or genuinely blocked.
argument-hint: <epic-id>
---

Work the beads epic `$ARGUMENTS` to completion, story by story, without stopping between stories.

## Setup (once)

1. `bd show $ARGUMENTS` — confirm it's an epic, list its children.
2. Branch check: `git status` then confirm current branch is `$ARGUMENTS`.
   - If it already exists: `git checkout $ARGUMENTS`.
   - If not: `git checkout main && git pull && git checkout -b $ARGUMENTS`.
3. Do **not** merge to main or push at any point during this loop — that happens only after
   the human reviews the finished epic.

## Per-story loop — repeat until stop condition

For each iteration:

1. `bd ready` (or `bd show $ARGUMENTS` filtered to open/unblocked children) to find the next
   unblocked story belonging to this epic. Prefer lowest ID / highest priority when multiple
   are ready.
2. **Stop condition**: if no ready child stories remain under this epic, stop the loop (see
   "End of epic" below). Do not ask the user first — this is the designed exit point.
3. `bd show <story>` — read the full description and acceptance criteria.
4. `bd update <story> --claim` (or `--status=in_progress`).
5. Research with `mcp__tokensave__tokensave_context(task=..., mode="plan")` first, per this
   repo's Story Planning Workflow. Fall back to `Read`/`Grep` only for files you'll edit
   directly or non-code content tokensave can't index. Do **not** invoke interactive Plan
   Mode (`EnterPlanMode`/`ExitPlanMode`) for this — it would block on a human per story,
   defeating the point of this loop. Reason through the approach yourself and go straight to
   implementation.
6. Implement the change.
7. Run quality gates relevant to the change (typically `flox activate -- bash -c 'export
   PATH="$HOME/go/bin:$PATH"; make check'`; add `make frontend-lint` if frontend files
   changed). Fix failures yourself before proceeding.
8. Stage and commit: `git add <changed files> .beads/issues.jsonl`, commit message
   `<type>: <summary> (<story-id>)` following Conventional Commits.
9. `bd update <story> --notes "Files: ...\nApproach: ..."` documenting what changed and why.
10. `bd close <story>`.
11. Immediately go back to step 1 for the next story — no user turn, no summary in between.
    Only pause mid-loop if you hit a genuine blocker (ambiguous requirements you can't
    resolve from the issue/codebase, a failing test you can't fix, a design decision only a
    human can make). In that case: `bd human <story>` to flag it with your specific question,
    leave the story in_progress, and either move on to the next independent ready story or,
    if nothing else is ready, stop and report the blocker.

## End of epic

When `bd ready` shows no more unblocked stories under this epic:

1. `bd stats` or `bd show $ARGUMENTS` to confirm every child story is closed.
2. `bd dolt push` (always safe).
3. Do **not** merge the epic branch to main, push it, or close the epic issue — leave that
   for the human to review and run explicitly, per this repo's epic-branch workflow.
4. Report a concise summary: stories closed (with IDs), any stories flagged with `bd human`
   and why, and confirmation that the branch is `$ARGUMENTS` with all work committed.
