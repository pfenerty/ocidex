---
name: work-epic
description: Autonomously plan and implement every ready story in a beads epic, one after another, stopping only when the epic is exhausted or genuinely blocked. Use when the user says "work epic <id>", "/work-epic <id>", or asks to work through an epic's stories.
argument-hint: <epic-id>
---

<!-- Vendored from ~/code/common/vendor/skills/work-epic/SKILL.md by `bin/hub vendor`.
     Edit the canonical copy there, not this one. -->

Work the beads epic `$ARGUMENTS` to completion, story by story, without stopping between stories.

This skill is shared by every repo. Where it says "the repo's CLAUDE.md", read that file and
follow it: its branching model, quality gates and commit conventions override the defaults here.

## Setup (once)

1. `bd show $ARGUMENTS`: confirm it's an epic and list its children. If it has no open
   children, stop and say so.
2. Read the repo's CLAUDE.md sections on branching, quality gates and session completion.
3. Branch, per the repo's CLAUDE.md. If it says nothing, use one branch per epic named
   `$ARGUMENTS`:
   - If it exists: `git checkout $ARGUMENTS`.
   - If not: `git checkout main && git pull --rebase && git checkout -b $ARGUMENTS`.
   If the repo uses one branch per issue instead, branch per story in the loop below.
4. Never merge to main or close the epic during this loop. That happens only after the human
   reviews the finished work.

## Per-story loop: repeat until the stop condition

1. Find the next ready child of this epic: `bd ready`, filtered to children of `$ARGUMENTS`
   (cross-check with `bd show $ARGUMENTS`). Prefer highest priority, then lowest ID.
2. **Stop condition**: if no ready child stories remain, go to "End of epic". Don't ask the
   user first; this is the designed exit.
3. `bd show <story>`: read the full description and acceptance criteria.
4. `bd update <story> --claim`.
5. Research. If tokensave is available (`.tokensave/` exists), start with
   `tokensave_context(task=..., mode="plan")`; read files directly only when you're about to
   edit them or tokensave can't index them. Do **not** enter interactive Plan Mode
   (`EnterPlanMode`): it blocks on a human every story, which defeats the loop. Reason through
   the approach yourself and implement.
6. Implement the change.
7. Run the quality gates the repo's CLAUDE.md lists for this kind of change (prefixed with
   `flox activate --` when the shell isn't already in the repo's Flox env). Fix failures
   yourself before moving on.
8. Stage and commit: `git add <changed files> .beads/issues.jsonl`, message
   `<type>: <summary> (<story-id>)` per Conventional Commits.
9. `bd update <story> --notes "Files: ...\nApproach: ..."`: what changed and why.
10. `bd close <story>`, then commit the updated `.beads/issues.jsonl` (amend the story commit
    if nothing else happened in between).
11. Go straight back to step 1. No user turn and no summary between stories.

**Genuine blockers only** (ambiguous requirements the issue and code can't resolve, a failure
you can't fix, a decision only a human can make): `bd human <story>` with your specific
question, leave the story in_progress, and move on to the next independent ready story. If
nothing else is ready, stop and report.

New work discovered along the way: `bd create` it under this epic (`--parent $ARGUMENTS`) if it
must land before the epic is done; otherwise file it standalone and mention it in the summary.

## End of epic

1. `bd show $ARGUMENTS`: confirm every child is closed, or list which aren't and why.
2. Push the branch if the repo's CLAUDE.md says branch pushes are safe (for example, ocidex: no
   CI on branch pushes). Otherwise leave it local and say so.
3. Do **not** merge to main, close the epic, or delete the branch.
4. Report briefly: stories closed (IDs), stories flagged with `bd human` and why, follow-up
   issues filed, the branch name, and whether it was pushed. Then give the merge command from the
   repo's CLAUDE.md for the human to run after review.
