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
- build
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

with network access and record the result.

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

If `gokui` binary is generated locally during checks, remove it after validation:

```sh
rm -f gokui
```

## 6) Release Evidence Record

Record release evidence using:

- [RELEASE_EVIDENCE_TEMPLATE.md](RELEASE_EVIDENCE_TEMPLATE.md)
- `make release-evidence` (creates `releases/evidence/<timestamp>-<commit>.md`)

At minimum, capture:
- commit SHA
- executed commands
- pass/fail result per gate
- vulnerability check result (or offline exception with follow-up run)
