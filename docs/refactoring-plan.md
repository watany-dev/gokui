# Refactoring Execution Plan

This document is a short-term execution plan for the current open refactoring
issues. It does not replace `ROADMAP.md`; use the roadmap for product direction
and use this file to order the refactoring queue.

## Scope

- Target issues: #2 through #19 in `watany-dev/gokui`.
- Baseline: current local code already contains several planned packages
  (`internal/rule`, `internal/safefs`, `internal/report`, `internal/skill`,
  split `internal/scan` files, and policy enum helpers), while `internal/app`
  still owns major command orchestration and compatibility contracts.
- Non-goal: changing CLI behavior, JSON/SARIF contracts, release-check error
  codes, or `ROADMAP.md` in this pass.

## Current Local Progress

As of the current local branch, the working tree should be clean between
increments. Earlier uncommitted validation-test work has been committed, and the
branch now contains several behavior-preserving extraction commits.

Recent completed increments:

- install/update/lock validation helpers split into focused files under
  `internal/app`.
- inspect/vet/update/fetch output writers and command dependency defaults split
  into focused files under `internal/app`.
- fetch/inspect/vet argument parsing split into focused parser files.
- supported command format checks centralized in `internal/app/args.go`.
- typed CLI format helpers added under `internal/cli/format`; command format
  support checks, parser defaults, pre-parse format detection, structured
  output checks, and success-output routing now use the typed constants.
- structured-error routing now uses typed formats internally, shared JSON/SARIF
  error-report write helpers, and a `lock verify` structured-error emit helper.
- pre-parse structured format detection is centralized while preserving the
  existing priority order for ambiguous argument lists.
- command parse-error report construction is split into command-specific helper
  functions for fetch, inspect/vet, install, update, and lock verify.
- parse-error structured writer dispatch is centralized, and all command
  parsers now read `--format` through one helper while preserving current error
  text.
- value-flag parsing for `--out`, `--target`, `--profile`, and `--override`
  now goes through a shared helper while preserving current missing-value errors.
- parser handling for repeated source arguments, unknown options, optional
  `lock verify` paths, and rejected `update` positionals now goes through
  shared helpers while preserving current error text.
- command parser value-flag dispatch is centralized; fetch, inspect, vet,
  install, update, and lock verify now share the same `--flag value` /
  `--flag=value` matching path and missing-value errors.
- boolean flag dispatch now uses the same parser-helper pattern; `update
  --dry-run` no longer has command-specific flag matching inline in the
  positional/unknown-option branch.
- parse-error output fallback is centralized; command runners now share the
  structured-output dispatch and human usage fallback for argument parsing
  failures while keeping command-specific report construction.
- JSON/SARIF structured-error emitter plumbing is centralized for fetch,
  install, update, and lock verify; inspect keeps its `review-json` special
  case until the inspect/vet report boundary is refactored.
- parser positional policy is centralized for single-source commands, optional
  `lock verify` paths, and commands that reject positionals; per-command loops
  no longer branch directly on option-vs-positional errors.
- parser loop dispatch now goes through a shared command-argument dispatcher
  that applies value flags, boolean flags, then positional policy in one place.
- command parser flag sets now use a reusable parser spec wrapper so each
  command declares value flags, boolean flags, and positional policy separately
  from loop execution.
- repeated parser spec handlers for common `--format`, `--target`, `--profile`,
  single-source positional, optional-path positional, and no-positional policies
  now use shared handler constructors.
- app-level inspect findings now carry `policy.Severity` internally while JSON,
  SARIF, compact, review, human output, install locks, and update risk scoring
  keep their existing string wire contracts.
- scan findings now carry the catalog `rule.Severity` type instead of raw
  strings, and app conversion to policy/wire severities happens at explicit
  boundaries.
- stable opened/current file checks now have package-level helpers in
  `internal/safefs`; app-specific `ensure*Stable*` functions are thin
  command/error-policy adapters.
- production install/update/lock wire structs now use
  `policy.SeverityOverrideAudit` directly; the old app-local alias is test-only
  compatibility for existing contract tests.
- SARIF error document construction now uses a shared helper for structured
  error rule ID resolution while keeping command-specific SARIF properties at
  the output boundary.
- SARIF findings-to-rules/results construction moved into `internal/report`;
  app-level inspect/fetch/install/update builders now adapt command findings
  into report findings before setting command-specific SARIF properties.
- SARIF file-location construction now lives in `internal/report`, and
  lock-verify drift results use the shared helper.
- SARIF rule/result construction now lives behind `internal/report` helpers,
  and lock verify uses the shared rule/result builders.
- SARIF rule/result sorting now lives behind `internal/report` helpers; lock
  verify no longer owns generic SARIF sort logic.

Validation already run after the latest parser/format increments:

```sh
go test ./internal/app -run 'Fetch|Args'
go test ./internal/app ./internal/cli/exitcode
go test ./internal/app -run 'Inspect|Vet|Args'
go test ./internal/app
go test ./internal/app -run 'Args|Fetch|Inspect|Vet|Install|Update|LockVerify'
go test ./internal/app -run 'Inspect|Vet|Update|JSON|SARIF|Compact|Review'
go test ./internal/app -run 'Fetch|Install|LockVerify|JSON|SARIF|Compact'
go test ./internal/app -run 'Error|JSON|SARIF|Fetch|Install|Update|Inspect|Vet|LockVerify'
go test ./internal/app -run 'LockVerify|Error|JSON|SARIF'
go test ./internal/app -run 'Args|Error|JSON|SARIF|Review|Fetch|Inspect|Vet|Install|Update|LockVerify'
go test ./internal/app -run 'Inspect|Vet|Args|Error|JSON|SARIF|Review'
go test ./internal/app -run 'Update|LockVerify|Args|Error|JSON|SARIF'
go test ./internal/app -run 'Fetch|Install|Args|Error|JSON|SARIF'
go test ./internal/app -run 'Args|Error|JSON|SARIF|Review|Fetch|Inspect|Vet|Install|Update|LockVerify'
go test ./internal/app -run 'Args|Fetch|Inspect|Update|Error|JSON|SARIF'
go test ./internal/app -run 'Args|Install|Vet|LockVerify|Error|JSON|SARIF|Review'
go test ./internal/app -run 'Args|Fetch|Install|Update|Error|JSON|SARIF'
go test ./internal/app -run 'Args|Install|Vet|Error|JSON|SARIF|Review'
go test ./internal/app
go test ./internal/app -run 'Args|Error|JSON|SARIF|Review|Fetch|Inspect|Vet|Install|Update|LockVerify'
go test ./internal/app -run 'Update|Args|Error|JSON|SARIF'
go test ./internal/app -run 'Args|Error|JSON|SARIF|Review|Fetch|Inspect|Vet|Install|Update|LockVerify'
go test ./internal/app -run 'Error|JSON|SARIF|Fetch|Install|Update|LockVerify'
go test ./internal/app -run 'Args|Fetch|Inspect|Vet|Install|Update|LockVerify|Error|JSON|SARIF|Review'
go test ./internal/app -run 'Args|Fetch|Inspect|Vet|Install|Update|LockVerify|Error|JSON|SARIF|Review'
go test ./internal/app -run 'Args|Fetch|Inspect|Vet|Install|Update|LockVerify|Error|JSON|SARIF|Review'
go test ./internal/app -run 'Error|SARIF|JSON|Fetch|Inspect|Install|Update|LockVerify'
go test ./internal/report ./internal/app -run 'SARIF|Inspect|Fetch|Install|Update'
go test ./internal/report ./internal/app -run 'SARIF|LockVerify'
go test ./internal/report ./internal/app -run 'SARIF|LockVerify'
go test ./internal/report ./internal/app -run 'SARIF|LockVerify'
go test ./internal/app -run 'Args|Fetch|Inspect|Vet|Install|Update|LockVerify|Error|JSON|SARIF|Review'
go test ./internal/app -run 'Inspect|Vet|Install|Update|Severity|JSON|SARIF|Compact|Review'
go test ./internal/scan ./internal/app -run 'Finding|Inspect|Vet|Install|Update|Severity|JSON|SARIF|Compact|Review'
go test ./internal/safefs ./internal/app -run 'Stable|Install|LockVerify|SourceMetadata|URLScan|Digest|Copy|Hash'
go test ./internal/app -run 'SeverityOverride|Install|Update|Lock'
make test
```

Current inventory notes:

- #7 is partially represented by `internal/rule`; keep open until scattered
  app/source rule constants are fully catalog-backed. The audit found the
  catalog and scan registry tests present, but command error-code constants and
  GitHub fetch guard errors still need an explicit catalog boundary decision.
- #10 is partially represented by shared SARIF document/types in
  `internal/report`; keep open until remaining command-specific SARIF property
  and structured-error builders are reduced to a common builder/config shape.
- #12 is represented by `source.GitHubFetcher`, option-based configuration, and
  option-based tests; candidate to close after repository write access is
  available.
- #13 is represented by split `internal/scan` implementation and test files;
  candidate to close after repository write access is available.
- #14 is represented by `scan.Finding` creation through `internal/rule` values
  and registry sync tests; candidate to close after repository write access is
  available.
- #15 is partially represented by `internal/safefs` stable/root/path helpers;
  the remaining app-specific `ensure*Stable*` wrappers are now thin policy/error
  adapters over shared `safefs` helpers, so this is a candidate to close after
  repository write access is available.
- #16 is represented by `internal/limitio` strict copy/hash helpers and related
  `internal/safefs` path helpers; candidate to close after repository write
  access is available.
- #17 is represented by `internal/policy` profile/severity types,
  `internal/cli/exitcode`, typed app command returns, typed scan findings, and
  typed app findings. Remaining severity strings are wire-boundary fields or
  JSON keys, so this is a candidate to close after repository write access is
  available.
- #18 is represented by `internal/policy/override.go` and
  `SeverityOverrideAuditSet`; production app structs/functions use
  `policy.SeverityOverrideAudit` directly, so this is a candidate to close after
  repository write access is available.
- #3, #4, #5, and #19 are partially represented but still need final audit before
  closing because `internal/app` remains the compatibility owner for command
  orchestration and many contract tests.
- GitHub issue write access was unavailable during the latest audit
  (`403 Resource not accessible by integration`), so no issue comments or
  closures were applied remotely.

## Recommended Order

### 1. Confirm Inventory

Confirm which open issues are already partially implemented locally, then update
issue descriptions or close completed follow-up issues before moving code again.

Primary issues:

- #2: split `internal/app` according to the roadmap packages.
- #3: move real implementations into `internal/skill`, `internal/install`, and
  `internal/report`.
- #7, #10, #13, #14, #15, #16, #17, #18, #19: several items appear partially or
  mostly represented in the current tree and need explicit issue-by-issue audit.

Validation:

```sh
git status --short
go test ./internal/rule ./internal/safefs ./internal/report ./internal/skill ./internal/scan ./internal/policy ./internal/limitio
make test
```

### 2. Finish Foundation Types

Finish or verify the low-level typed foundations before touching CLI command
orchestration. These changes are easiest to validate in isolation and reduce
stringly typed behavior in later steps.

Primary issues:

- #7: central rule registry.
- #14: route scan findings through the registry.
- #15: common stable-file/root checks in `internal/safefs`.
- #16: strict copy/hash/limit helpers in `internal/limitio` and path helpers in
  `internal/safefs`.
- #17: typed `PolicyProfile`, `Severity`, and exit codes.
- #18: `severityOverrideAudit` as an audit-set value type.

Validation:

```sh
go test ./internal/rule ./internal/scan ./internal/safefs ./internal/limitio ./internal/policy ./internal/cli/exitcode
make test
```

### 3. Extract Leaf Domains

Move leaf logic out of `internal/app` where there is little or no dependency on
command-level IO. Prefer package-local tests while preserving existing contract
tests in `internal/app`.

Primary issues:

- #3: `internal/skill` frontmatter/name/description validation.
- #3: `internal/report` compact/review/SARIF rendering primitives.
- #10: shared SARIF document/builder types without `inspect` naming.
- #13: split `internal/scan/scan.go` by topic without behavior changes.
- #19: split large tests in the same packages after code movement stabilizes.

Validation:

```sh
go test ./internal/skill ./internal/report ./internal/scan
go test ./internal/app -run 'Inspect|SARIF|Review|Frontmatter'
make test
```

### 4. Organize Update Evaluation

Refactor `update --dry-run` validation after the foundational rule/severity and
audit types are stable. Keep behavior unchanged and preserve existing JSON and
SARIF output contracts.

Primary issues:

- #6: table-drive `evaluateUpdateSkill` validation.
- #18: use the audit-set value type for override comparisons and validation.
- #9: identify the update wire/domain boundary, but defer broad wire conversion
  until step 8.

Validation:

```sh
go test ./internal/app -run 'Update|SeverityOverride|Lock'
make test
```

### 5. Introduce Dependency Injection

Replace test-only package globals with explicit dependency structs after leaf
logic is extracted. This lowers risk because the dependency surfaces will be
smaller and command-specific.

Primary issues:

- #11: remove package-global function variables used for tests.
- #12: convert the GitHub fetcher into a client struct.

Validation:

```sh
go test ./internal/source ./internal/app -run 'Fetch|GitHub|Install|Inspect'
go test -race ./internal/source ./internal/app
make test
```

### 6. Consolidate CLI Common Code

Unify command parsing, format detection, error envelopes, and exit codes once
dependencies are explicit. This is the point where cross-command CLI behavior
can be normalized without hiding domain movement inside the same diff.

Primary issues:

- #4: common error envelope/rendering.
- #5: unified argument and `--format` parsing.
- #17: typed exit codes in command returns.

Validation:

```sh
go test ./internal/app -run 'Args|Error|Exit|JSON|SARIF|Compact'
make check
make test
```

### 7. Split Inspect and Vet Internals

Remove the in-process JSON round trip only after the report rendering and CLI
error path are centralized. `inspect` and `vet` should share a domain evaluator
and diverge only at command policy/rendering boundaries.

Primary issues:

- #8: `vet` calls the inspect/evaluation domain directly instead of invoking
  `runInspect --format json`.
- #3: any remaining inspect evaluator code moves into `internal/skill` or a
  clearly named evaluator package.
- #9: keep JSON representation at the output boundary.

Validation:

```sh
go test ./internal/app -run 'Inspect|Vet|ReviewJSON|JSONContract'
make test
```

### 8. Separate Wire and Domain Types

After command paths are stable, separate domain values from JSON/SARIF wire
types. This is high blast-radius work and should not be mixed with extraction or
CLI parser changes.

Primary issues:

- #9: domain types without JSON tags, plus explicit wire conversion.
- #10: SARIF wire types remain in report-specific packages.
- #7 and #17: rule/severity/profile types should be used by domain values.

Validation:

```sh
go test ./internal/app -run 'JSONContract|RuleID|Lock|Report'
go test ./internal/report ./internal/install ./internal/source ./internal/policy
make test
```

### 9. Split `internal/app`

Perform the final `internal/app` package split only after the lower-level
contracts are explicit and tested. Keep this as a sequence of small moves:
command by command, with compatibility tests left in place until each command is
ported.

Primary issues:

- #2: split command orchestration toward `internal/cli/<command>` and roadmap
  domain packages.
- #3: finish any remaining domain moves.
- #4 and #5: command common code lives under `internal/cli`.
- #19: move command tests alongside their new packages once command boundaries
  are stable.

Validation:

```sh
go test ./internal/cli/... ./internal/app
make check
make test
make build
```

## Issue Map

| Issue | Recommended stage | Notes |
| --- | --- | --- |
| #2 | 9 | Final package split; keep until dependencies and wire contracts are ready. |
| #3 | 3, 7, 9 | Extract leaf domain first, then finish command-level leftovers. |
| #4 | 6 | Do after DI and rendering primitives are stable. |
| #5 | 6 | Pair with #4 so parse failures and error envelopes share one path. |
| #6 | 4 | Isolated update cleanup; avoid mixing with wire/domain conversion. |
| #7 | 2 | Foundation for scan, report, and rule inference. |
| #8 | 7 | Depends on inspect evaluator and report rendering separation. |
| #9 | 8 | High blast-radius; defer until behavior is well covered. |
| #10 | 3, 8 | Shared SARIF primitives first, wire cleanup later. |
| #11 | 5 | Easier after leaf functions have moved out of `internal/app`. |
| #12 | 5 | Can be paired with #11 but validated in `internal/source` first. |
| #13 | 3 | File split only; should remain behavior-preserving. |
| #14 | 2 | Complete after rule registry shape is fixed. |
| #15 | 2 | Foundation utility extraction. |
| #16 | 2 | Foundation utility extraction. |
| #17 | 2, 6, 8 | Define enums early, thread exit codes through CLI later. |
| #18 | 2, 4 | Define value type early, adopt in update/lock verification next. |
| #19 | 3, 9 | Split tests after the related package boundaries settle. |

## Next Concrete Increments

The next work should stay behavior-preserving and commit after each validation
slice:

1. Audit #7, #10, #12, #13, #15, #16, #17, and #18 against the current code and
   close or update any issues whose requested implementation is now present.
2. Continue #5 by extracting any remaining duplicated parser spec declarations
   only where that stays readable. Keep current error strings and pre-parse
   structured-output detection stable while doing this.
3. Continue #4/#10 by extracting any remaining command-specific structured-error
   branching outside parse-error handling where it can be done without changing
   current error strings, fallback source/target fields, `review-json`
   handling, command-specific SARIF properties, or structured output contracts;
   defer changing report wire structs until #9.
4. Continue #8 only after #4 has a stable command error path and inspect report
   rendering remains covered by contract tests.

## Commit Hygiene

For each implementation increment:

```sh
git status --short
git diff --check
make test
```

When committing this document, stage only:

```sh
git add docs/refactoring-plan.md
git commit -m "docs: add refactoring execution plan"
```
