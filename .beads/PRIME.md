<!-- beads-public-repo: vendored by `hub vendor` from pfenerty/planning vendor/beads-prime-public.md.
     bd's default `bd prime --export` text (bd 1.3.2), with the Memory rule replaced. Regenerate on beads upgrades. -->
# Beads Workflow Context

> **Context Recovery**: Run `bd prime` after compaction, clear, or new session
> Hooks auto-call this in Claude Code and Codex when a beads workspace is resolved

# 🚨 SESSION CLOSE PROTOCOL 🚨

**CRITICAL**: Before saying "done" or "complete", you MUST run this checklist:

```
[ ] 1. bd close <id1> <id2> ...   (close completed issues)
[ ] 2. run quality gates        (tests, linters, builds when relevant)
[ ] 3. git status               (check what changed)
[ ] 4. follow active profile    (conservative: report handoff; team-maintainer: commit/sync/push if enabled)
```

**Policy:** Conservative is the default. Commit, sync, or push only when the active user, orchestrator, or repository profile grants that authority.

## Core Rules
- **Default**: Use beads for ALL task tracking (`bd create`, `bd ready`, `bd close`)
- **Prohibited**: Do NOT use TodoWrite, TaskCreate, or markdown files for task tracking
- **Workflow**: Create beads issue BEFORE writing code, mark in_progress when starting
- **Memory**: This repo is PUBLIC, and its beads DB (issues and memories alike) is published on GitHub. Do NOT use `bd remember`; `bd-sync` refuses to sync while memories exist. Put durable project knowledge in this repo's CLAUDE.md, where it is reviewed. Keep anything private out of this repo entirely.
- Persistence you don't need beats lost context
- Default: do not commit, push, or run dolt remote sync without explicit authority. Team-maintainer behavior is opt-in and still subordinate to user/orchestrator instructions.
- Git workflow: conservative by default; commit/push only with explicit user/orchestrator or team-maintainer authority
- Session management: check `bd ready` for available work

## Essential Commands

### Finding Work
- `bd ready` - Show issues ready to work (no blockers)
- `bd list --status=open` - All open issues
- `bd list --status=in_progress` - Your active work
- `bd show <id>` - Detailed issue view with dependencies

### Creating & Updating
- `bd create --title="Summary of this issue" --description="Why this issue exists and what needs to be done" --type=task|bug|feature --priority=2` - New issue
  - Priority: 0-4 or P0-P4 (0=critical, 2=medium, 4=backlog). NOT "high"/"medium"/"low"
- `bd create ... --parent=<id>` - Hierarchical child (task under epic, subtask under task; inherits parent labels)
- `bd update <id> --claim` - Claim work
- `bd unclaim <id>` - Release stuck issue (agent crashed)
- `bd update <id> --assignee=username` - Assign to someone
- `bd update <id> --if-assignee=<expected> --assignee=<new>` - Atomic reassign: applies only if the assignee still matches (--if-status=<expected> guards status; --if-assignee='' requires unassigned). Mismatch exits non-zero with nothing written — never retry blindly
- `bd update <id> --title/--description/--notes/--design` - Update fields inline
- `bd close <id>` - Mark complete
- `bd close <id1> <id2> ...` - Close multiple issues at once (more efficient)
- `bd close <id> --reason="explanation"` - Close with reason
- **Tip**: When creating multiple issues/tasks/epics, use parallel subagents for efficiency
- **WARNING**: Do NOT use `bd edit` - it opens $EDITOR (vim/nano) which blocks agents

### Dependencies & Blocking
- `bd dep add <issue> <depends-on>` - Add dependency (issue depends on depends-on)
- `bd blocked` - Show all blocked issues
- `bd show <id>` - See what's blocking/blocked by this issue

### Sync & Collaboration
- `bd dolt push` - Push beads to Dolt remote
- `bd dolt pull` - Pull beads from Dolt remote
- `bd search <query>` - Search issues by keyword

### Project Health
- `bd stats` - Project statistics (open/closed/blocked counts)
- `bd doctor` - Check for issues (sync problems, missing hooks)
- `bd doctor --check=conventions` - Check for convention drift (lint, stale, orphans)

### Quality Tools
- `bd create --validate` - Check description has required sections
- `bd create --acceptance="criteria"` - Set acceptance criteria (checked by --validate)
- `bd create --design="decisions"` - Record design decisions
- `bd create --notes="context"` - Add supplementary notes
- `bd config set validation.on-create warn` - Auto-validate on every create
- `bd lint` - Check existing issues for missing sections

### Lifecycle & Hygiene
- `bd defer <id> --until="date"` - Defer work to a future date
- `bd supersede <id> --with=<new-id>` - Mark issue as superseded
- `bd close <id> --suggest-next` - Show newly unblocked issues after closing
- `bd stale` - Find issues with no recent activity
- `bd orphans` - Find issues with broken dependencies
- `bd preflight` - Pre-PR checks (lint, stale, orphans)
- `bd human <id>` - Flag for human decision (list/respond/dismiss)

### Structured Workflows
- `bd formula list` - See available workflow templates
- `bd mol pour <name>` - Start structured workflow from formula

## Common Workflows

**Starting work:**
```bash
bd ready           # Find available work
bd show <id>       # Review issue details
bd update <id> --claim  # Claim it
```

**Completing work:**
```bash
bd close <id1> <id2> ...    # Close all completed issues at once
git status                  # Check changed files
# Conservative/minimal/default: report status and proposed commands; wait for approval
# Team-maintainer opt-in only, unless current instructions forbid it:
# git add . && git commit -m "..."
# bd dolt push
# git push
```

**Creating dependent work:**
```bash
# Run bd create commands in parallel (use subagents for many items)
bd create --title="Implement feature X" --description="Why this issue exists and what needs to be done" --type=feature
bd create --title="Write tests for X" --description="Why this issue exists and what needs to be done" --type=task
bd dep add beads-yyy beads-xxx  # Tests depend on Feature (Feature blocks tests)
```
