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

`release-check` fails closed when build/SARIF output paths include symlink
components, when either output already exists, or when build and SARIF outputs
resolve to the same path.
Preflight rejections include machine-readable error codes:
`RC_PREFLIGHT_BUILD_OUT_INVALID`, `RC_PREFLIGHT_SARIF_OUT_INVALID`,
`RC_PREFLIGHT_BUILD_OUT_SYMLINK`, `RC_PREFLIGHT_SARIF_OUT_SYMLINK`,
`RC_PREFLIGHT_OUTPUT_PATH_CONFLICT`, `RC_PREFLIGHT_BUILD_OUT_EXISTS`, and
`RC_PREFLIGHT_SARIF_OUT_EXISTS`.
Release-check build/SARIF output paths must also be non-root file paths and must resolve
under the repository root, and must not be directory-like paths ending with `/` or
located under `.git/`.
`make inspect-sarif` output paths must resolve under the repository root and
must resolve outside `.git/`.
`make inspect-sarif` output paths must not contain `..` path segments.
Output-path safety preflight checks run before format/test/race/vuln gate
steps.

To override the isolated release-check build artifact path:

```sh
make release-check RELEASE_CHECK_BUILD_OUT=.cache/custom/gokui-release-check
```

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
- release-check stderr error codes:
  - see `README.md` -> `Automation Error Codes` -> `release-check`
- Exit code contract:
  - success: `0`
  - fatal error: `1`
  - policy rejection / drift: `2` (where applicable)
- Documentation sync tests in `internal/app/docs_sync_test.go` and related contract tests.

## 5) Build Artifact Hygiene

`gokui` is ignored as a local build artifact, so tracked-file clean checks are
not affected by local binary rebuilds.

If you need an explicit cleanup or alternate path:

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

For evidence scripts, clean-tree checks include tracked and untracked
(non-ignored) files (`git status --short`), and build output is isolated to
`.cache/gokui-release-evidence`.
Evidence file names end with `-offline-audit.md` or `-online-audit.md`
depending on whether `--with-vuln` is enabled.
Evidence scripts fail closed when git `HEAD` commit SHA cannot be resolved as
canonical lowercase 40-hex.
Release scripts fail closed when repository-root/output/log paths include
symlink components or expected output/log files already exist.
Evidence and SARIF outputs are created atomically and written via open file
descriptors to reduce path-swap race windows during script execution.
Staged temporary evidence/SARIF files are also removed when finalization
collides with an existing destination path.
When offline gate steps fail, evidence scripts keep failing build artifacts for
investigation and skip subsequent vuln/cleanup steps.
Cleanup-removal failures are tagged with machine-readable code
`RC_CLEANUP_REMOVE_FAILED`.
When one or more removals fail, a summary line is emitted with
`RC_CLEANUP_REMOVE_FAILED_SUMMARY`.

| Release-check code | Typical trigger |
| --- | --- |
| `RC_PREFLIGHT_BUILD_OUT_INVALID` | `RELEASE_CHECK_BUILD_OUT` is root-like (`/`, `.`, empty), ends with `/`, resolves outside the repository root, or resolves under `.git/` |
| `RC_PREFLIGHT_SARIF_OUT_INVALID` | `RELEASE_CHECK_SARIF_OUT` is root-like (`/`, `.`, empty), ends with `/`, resolves outside the repository root, or resolves under `.git/` |
| `RC_PREFLIGHT_BUILD_OUT_SYMLINK` | Build output path or ancestor contains a symlink component |
| `RC_PREFLIGHT_SARIF_OUT_SYMLINK` | SARIF output path or ancestor contains a symlink component |
| `RC_PREFLIGHT_OUTPUT_PATH_CONFLICT` | Build and SARIF outputs resolve to the same absolute path |
| `RC_PREFLIGHT_BUILD_OUT_EXISTS` | Build output path already exists before gate execution |
| `RC_PREFLIGHT_SARIF_OUT_EXISTS` | SARIF output path already exists before gate execution |
| `RC_CLEANUP_REMOVE_FAILED` | Cleanup failed to remove one output path |
| `RC_CLEANUP_REMOVE_FAILED_SUMMARY` | Cleanup failed to remove one or more output paths (summary line with count) |

At minimum, capture:
- mode (`offline` or `online`)
- commit SHA
- executed commands
- pass/fail result per gate
- vulnerability check result (or offline exception with follow-up run)
