# AI in OCIDex

Most of the code in this project was written by AI — specifically [Claude](https://claude.ai/) (Anthropic), used through [Cursor](https://cursor.com/).

## How it works

The repository includes a `CLAUDE.md` file that describes the project's structure, tech stack, conventions, and constraints. This file is loaded as context at the start of every AI session, so the AI operates within the project's established patterns.

A typical cycle looks like: the developer describes what to build or change, the AI implements it across however many files are involved, the developer reviews the result. This applies to everything — features, refactoring, tests, documentation, and the [Architecture Decision Records](adr/) that define the project's technical direction.

## What the human does

- **Direction.** Deciding what to build, which technologies to use, what's good enough, and what needs to change.
- **Review.** Everything the AI produces is reviewed and approved before it ships.

## Why document this

AI-assisted development is common and becoming more so. Being straightforward about it is more useful than pretending otherwise.
