# Contributing to gokui

Thanks for your interest in contributing. gokui is a quarantine gate for
Agent Skill bundles; correctness and fail-closed behavior matter more here
than feature velocity, and the contribution process reflects that.

## Prerequisites

- Go 1.26 or later (see `go.mod`).
- `make` and a POSIX shell (the gates are Makefile-driven).

## Development Loop

The Makefile encodes the whole process:

```sh
make check   # fmt-check, lint, typecheck, deadcode, coverage gate
make test    # go test ./...
make build   # build ./cmd/gokui
```

Before sending a PR, `make check` and `make test` must both pass. CI runs
the same gates on a three-OS matrix (Linux, macOS, Windows) with race
detection, so platform-conditional code needs `runtime.GOOS` guards rather
than assumptions.

### Coverage threshold

Total test coverage is enforced at **95%** across all packages
(`scripts/check-coverage.sh`, run as part of `make check` via `coverage`).
New code generally needs tests for its error paths, not just the happy
path — most of the codebase's coverage lives in failure-handling branches,
which is deliberate for a fail-closed tool.

Tests that simulate permission errors with `os.Chmod` should skip when
running as root (`os.Getuid() == 0`), since mode bits do not restrict root:

```go
if os.Getuid() == 0 {
    t.Skip("chmod restrictions do not apply to root")
}
```

## Fixture Conventions

Skill-bundle test fixtures live under `fixtures/`. Each is a minimal
directory with a `SKILL.md` demonstrating one scenario:

- `clean-skill` — passes inspection; used for happy-path contracts.
- `fake-prereq-skill` — rejected; the standard demo of a malicious pattern.
- Others cover structural failures (missing frontmatter, missing root).

When adding a detection rule, prefer adding a focused fixture (or extending
an existing scan test with inline file content via `t.TempDir()`) over
growing a shared fixture, so each fixture keeps a single clear purpose.

## Behavioral Contracts

Machine-readable outputs are stable contracts. If a change touches any of
these, update `README.md`, `ROADMAP.md`, and `RELEASE.md` together (the
docs-sync tests in `internal/app/docs_sync_test.go` enforce parts of this):

- exit codes (`0` pass, `2` rejected, `1` fatal)
- JSON/SARIF/compact/review-json output shapes and `error_code` values
- rule IDs and severities
- lockfile (`gokui.lock`) and install-report (`.gokui-report.json`) formats

Decisions must fail closed: when in doubt, an error should produce
`REJECTED` or a fatal error, never a silent `PASS`.

## Reporting Detection Gaps

A malicious pattern that gokui currently passes is the most valuable report
this project can receive. If the gap defeats an existing rule, report it
privately first (see [SECURITY.md](./SECURITY.md)). If it needs a brand-new
rule, an issue using the false-negative template is the right place.

## Pull Requests

- Keep changes small and reviewable; one concern per PR.
- Include tests in the same PR as the change they cover.
- Explain *why* in the PR description, especially for rule or policy
  changes — the threat being addressed matters as much as the diff.
