# Agent Instructions

**The full agent contract for this repo is [CLAUDE.md](CLAUDE.md)** — environment setup, code
conventions, the generated-file rules, branching, and the documentation map. Read it first.

This file covers only what is specific to agents working across the `~/code` repos.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files
<!-- END BEADS INTEGRATION -->

## Session Completion

Work is not complete until it is committed **and pushed**. Pushing the epic branch runs no CI —
the push pipeline's trigger is `{ on: PUSH, branch: "main" }` (`.tektonic/pipeline.ts`) — so
there is no reason to leave work stranded locally.

```bash
git add <changed files> .beads/issues.jsonl
git commit -m "..."
bd dolt push
git push                       # the epic branch; free
git status                     # MUST show "up to date with origin"
```

Merging to `main` is the one CI-triggering push (~70 min warm, 3 h timeout) — do it once per
epic, not once per story. Full workflow in [CLAUDE.md](CLAUDE.md#issue-tracking--branching).

## Cross-Repo Planning

`ocidex` is the downstream consumer of `apko-cicd` images (via `.tekton/tasks/*.yaml`) and `tektonic` (via `make tekton-synth`). Cross-cutting initiatives that span multiple repos are tracked in `~/code/common/` (issue prefix: `plan`).

- `bd list` here shows only this repo's issues — cross-repo hydration is not yet implemented in beads
- **Unified view:** `flox activate -d ~/code/ocidex -- nu ~/code/common/bd-all.nu`
- To create a cross-repo parent epic: `cd ~/code/common && bd create --title="..." --type=epic`
- When a local issue is part of a cross-repo initiative: `bd update <id> --notes "Parent epic: plan/<id>"`
- Upstream changes arrive as: new apko image tag → update `.tekton/tasks/*.yaml`; new tektonic version → `npm install`, `make tekton-synth`, commit regenerated YAML
