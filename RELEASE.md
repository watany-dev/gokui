# Release Checklist

This checklist standardizes pre-release and release-candidate verification.

## 1) Repository State

- Confirm the branch is up to date with intended release commit.
- Confirm working tree is clean.

```sh
git status --short
```

Expected: no output.

## 2) Full Quality Gate (Online)

Run the complete gate including vulnerability database checks:

```sh
make release-check
```

This runs:
- format check
- `go vet` + `staticcheck`
- typecheck (`go test -run '^$' ./...`)
- deadcode
- coverage threshold check
- full tests
- race tests
- build (isolated output: `.cache/gokui-release-check`, auto-cleaned)
- inspect SARIF smoke generation (`make inspect-sarif`)
- `govulncheck`

## 3) Offline Fallback

If vulnerability DB/network access is temporarily unavailable:

```sh
make release-check-offline
```

Before final release publication, rerun:

```sh
make vuln
```

with network access and record the result. The default target runs with
`VULN_GOTOOLCHAIN=go1.26.3+auto` so standard-library checks use a patched
toolchain baseline.

## 4) Contract Spot-Checks

- JSON error contracts:
  - `fetch`, `inspect`, `install`, `update`, `lock verify`
- SARIF contract smoke check:
  - `make inspect-sarif` (expects reject exit code path and emits `inspect-results.sarif`)
- Exit code contract:
  - success: `0`
  - fatal error: `1`
  - policy rejection / drift: `2` (where applicable)
- Documentation sync tests in `internal/app/docs_sync_test.go` and related contract tests.

## 5) Build Artifact Hygiene

If `gokui` binary is generated locally during checks, remove it after
validation, or override the output path:

```sh
rm -f gokui
# or
make build BUILD_OUT=.cache/gokui-local
```

## 6) Release Evidence Record

Record release evidence using:

- [RELEASE_EVIDENCE_TEMPLATE.md](RELEASE_EVIDENCE_TEMPLATE.md)
- `make release-evidence` (creates `releases/evidence/<timestamp>-<commit>.md`)
- `make release-evidence-offline` (runs offline gate and creates `releases/evidence/<timestamp>-<commit>-offline-audit.md` with step logs)
- `make release-evidence-online` (runs offline gate + vuln check and creates `releases/evidence/<timestamp>-<commit>-online-audit.md` with step logs)

For evidence scripts, clean-tree checks are tracked-files only
(`git status --short --untracked-files=no`), and build output is isolated to
`.cache/gokui-release-evidence`.
Evidence file names end with `-offline-audit.md` or `-online-audit.md`
depending on whether `--with-vuln` is enabled.

At minimum, capture:
- mode (`offline` or `online`)
- commit SHA
- executed commands
- pass/fail result per gate
- vulnerability check result (or offline exception with follow-up run)
