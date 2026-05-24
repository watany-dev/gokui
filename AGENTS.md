# AGENTS.md

This repository uses a repo-local Codex guide and skills.

## Scope

This file defines the default working rules for Codex in this repository.
Repo-local skills should live under `skills/`.

## Project Overview

gokui is a quarantine gate for Agent Skill bundles.

The current product shape from `README.md` and `ROADMAP.md` is:

- strict quarantine-first workflow
- explicit separation of `fetch`, `inspect`, `install`, and `update`
- policy-driven installation with provenance and lockfile recording
- planned implementation language: Go

Current MVP command set:

```text
gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir>
gokui inspect <local-dir|zip|github-source>
gokui vet <local-dir|zip|tar>
gokui install <source> --target codex --profile strict
gokui update --dry-run
gokui lock verify
```

## Current Source Of Truth

Treat these as the primary project documents:

- `README.md`
- `ROADMAP.md`
- `AGENTS.md`

Keep those three aligned.

## Working Baseline

1. Inspect the repository before making assumptions about language, framework, build system, or test runner.
2. Prefer the commands and conventions already present in the repo over introducing new tooling.
3. Keep changes small, explicit, and easy to validate.
4. Update related docs when behavior, commands, or project structure change.

## Discovery Order

Before making changes, check the files that define how the project works:

- `README.md`
- `ROADMAP.md`
- CI workflows under `.github/workflows/`
- language/build manifests such as `go.mod`, `Makefile`, `package.json`, `pyproject.toml`, `Cargo.toml`
- source entry points and top-level docs

If those files do not exist, say so explicitly and proceed with the smallest reasonable assumption.

## Completion Requirements

Do not consider work complete until you have run the narrowest relevant validation available in the repository.

Examples:

- existing test command
- existing formatter or linter
- existing typecheck or build command

For this repository today, prefer:

- `make test`
- `make check`
- `make build`

If the repository does not yet define runnable validation commands, report that clearly instead of inventing a fake completion signal.

## Engineering Approach

### TDD When Practical

When the repo already has tests or a clear place for them:

1. write or update a failing test
2. implement the minimum change
3. refactor without changing behavior

### Tidy First

Separate structural cleanup from behavioral changes where practical.

- reduce nesting with guard clauses
- remove dead code when encountered
- extract helpers when they clarify intent
- normalize similar code paths
- keep comments short and only where code is not self-evident

### Iteration Size

Split work into the smallest meaningful increment and finish that increment completely before moving on.

## Planned Architecture

Use `ROADMAP.md` as the default implementation direction unless newer code or docs replace it:

- `cmd/gokui/main.go` for CLI entry
- `internal/source/`
- `internal/materialize/`
- `internal/skill/`
- `internal/scan/`
- `internal/policy/`
- `internal/install/`
- `internal/report/`

## Documentation Rules

- `README.md`: user-facing usage, install, and operation
- `ROADMAP.md`: design goals, phases, and implementation plan
- `AGENTS.md`: repo-specific instructions for Codex

When a command, workflow, or architecture decision changes, update the relevant document in the same task when possible.

## Planning Rules

When asked for a plan:

1. ground the plan in the current repo state
2. identify missing design or requirement inputs
3. keep steps independently verifiable
4. note risks, dependencies, and affected files
