# Roadmap

This roadmap follows gokui's core position: it is a quarantine gate for Agent
Skill bundles, not a convenience-first package manager.

## Current Implementation Snapshot (May 24, 2026)

The following items are implemented in the current codebase and validated by
tests/CI:

- CLI commands: `fetch`, `inspect`, `vet`, `install`, `update --dry-run`, `lock verify`
- Quarantine-safe archive materialization for inspect/install flows
- Strict skill frontmatter validation and markdown/script scanning
- Local-dir inspect source hardening (reject symlinked source paths/components and symlinked `SKILL.md`; require regular-file `SKILL.md`)
- Symlink target hardening for `fetch --out`, `install --target`, `update --target`, and `lock verify` input paths (including symlink path components)
- Lock/source-metadata/report read-path hardening with symlink component rejection and regular-file enforcement
- Source metadata write-path hardening with symlink component rejection and non-regular target rejection
- Install atomic finalize hardening for symlinked target entries
- Install idempotent-reuse hardening via strict existing-lock structural validation before provenance match
- Install idempotent-reuse hardening via installed-content/root-hash drift verification (and GitHub metadata integrity for GitHub-origin installs)
- Install idempotent-reuse hardening via install-report integrity verification during reuse checks
- Install source-copy hardening with strict byte-limit writes and overflow cleanup
- Install source-copy and digest root hardening for symlink/non-directory root rejection
- Fetch atomic finalize hardening for symlinked output entries
- Update dry-run hardening for symlinked target entries, symlinked URL/executable scan inputs, and non-directory/symlink scan roots
- Scan/update walker hardening for symlink/non-directory root rejection and
  non-regular file rejection before reads
- extensionless script coverage for shebang files and executable-bit files in scan target classification
- UTF-8 BOM-prefixed extensionless shebang script coverage in scan target classification
- Commit-pinned GitHub source fetch and install/update/verify provenance checks
- Commit-pinned GitHub source enforcement for `inspect` (floating refs rejected)
- GitHub archive network hardening (strict redirect cap/constraints + response content-type/encoding validation)
- GitHub archive strict stream-size enforcement with overflow-write prevention and cleanup
- GitHub source parser length bounds (input and owner/repo/path/ref segments)
- Atomic install with `.gokui-report.json` and `gokui.lock`
- Built-in install policy profiles: `strict`, `team`, `research`
- User policy loading from `~/.config/gokui/policy.toml` (`default_profile`)
- Repository policy loading from nearest-ancestor `.gokui-policy.toml` for `local-dir` install/update source evaluation
- Policy-driven CLI override controls via `policy.toml` (`overrides.enabled`, `overrides.allowed_rule_ids`)
- Profile-specific reject severity controls via `policy.toml` (`profiles.<name>.reject_severities`)
- `vet` policy resolution for effective profile/reject severities via user policy (`GOKUI_POLICY_PATH`/`~/.config/gokui/policy.toml`) and nearest-ancestor repository policy precedence for `local-dir` sources
- Lock drift verification with per-check machine-readable codes
- Stable JSON output contracts for all MVP commands
- Machine-readable `error_code` support across command failure paths
- SARIF output for `inspect` (`--format sarif`) for CI/code scanning integration
- SARIF output for `fetch` (`--format sarif`) for quarantine provenance export
- SARIF output for `install` (`--format sarif`) for policy findings export
- SARIF output for `update --dry-run` (`--format sarif`) for dry-run finding export
- SARIF output for `lock verify` (`--format sarif`) for drift/check export
- structured SARIF fatal-error output for `inspect`, `vet`, `fetch`, `install`, `update`, and `lock verify`
- `vet` command for skill-author local-source validation (`local-dir|zip|tar`)
- compact summary output for `fetch`/`inspect`/`vet`/`install`/`update`/`lock verify` (`--format compact`) for CI logs
- README rule documentation with remediation notes for high-signal security findings
- severity override audit-trail fields in install/update JSON and lock policy metadata
- install `--override RULE_ID` support for explicit high-severity downgrade with audit trail recording
- update dry-run reporting for severity override applicability drift (`severity_override_diff`)
- update dry-run differential risk scoring (`risk_score`) with severity-and-signal model
- update dry-run new URL signal detection includes scheme-relative URL forms (`//host/...`), bracketed IPv6 URL forms, and case-insensitive `http(s)://` schemes
- update dry-run lock provenance consistency and canonical validation (`source.kind`/`source.input`/`source.type`, canonical `policy.profile`/`policy.decision`, lock skill snapshot digest/path sanity, and lock envelope integrity for `schema`/`name`/`installed_at`/`severity_overrides`/findings counters)
- lock/source metadata canonical digest and ref validation (`root_sha256`/per-file `sha256`, metadata `resolved_ref`/`skill_root_sha256`)
- canonical validation for severity override audit entries (`rule_id`, `previous_severity`, `effective_severity`, `source`, `applied_at`)
- severity override audit source-origin allowlist validation (`cli-override|policy-file`)
- non-negative lock findings summary validation for update/install/lock-verify guards
- strict install-report schema version validation during lock verify / idempotent reuse integrity checks
- update dry-run baseline integrity check against existing `.gokui-report.json` when present
- neutralized structured review export for inspect/vet (`--format review-json`)
- CI SARIF smoke job for inspect output generation and artifact capture
- CI setup-go hardening to resolve the latest available Go patch release
- `make vuln` hardened with patched Go toolchain baseline (`go1.26.3+auto`)
- automated offline release evidence collection with per-step logs
- automated online release evidence collection mode (includes vuln step)
- release-evidence gate hardening with isolated build output (`BUILD_OUT`) and tracked-file clean-tree checks (`git status --short --untracked-files=no`)
- release-check gate hardening with isolated build output (`RELEASE_CHECK_BUILD_OUT`) and automatic artifact cleanup
- release-evidence metadata mode annotation (`offline|online`) and mode-specific evidence filename suffixes (`-offline-audit.md` / `-online-audit.md`)
- URL risk classification for shortener hosts and raw-IP URLs (including scheme-relative `//host/...` forms, bracketed/zone-id IPv6 hosts, decimal/hex/octal and abbreviated/mixed-base dotted IPv4 hosts, and normalized trailing-dot/IDNA dot-variant hosts)
- shortener/paste-site URL risk classification includes configured subdomain matches
- URL risk classification for paste-site URLs and GitHub release asset URLs (including known GitHub CDN hosts, API release-asset forms on `api.github.com`/`uploads.github.com` such as `releases/assets/<asset_id>` and `releases/<release_id>/assets`, object-path forms, and `releases/latest/download` paths)
- URL risk classification for remote image URLs in markdown content
- raw HTML markup detection in markdown scanning
- markdown link-spoofing detection (display host vs target host mismatch), including inline and reference-style links (including spaced and one-line-break-separated reference forms), excluding unescaped image markdown forms
- bounded fuzzy/typoglycemia detection for common prompt-override phrases
- critical detection of Unicode Tags and bidi controls in scanned text
- critical detection of zero-width and disallowed C0/C1 controls in scanned text
- critical detection of variation selectors and ANSI/OSC escapes in scanned text
- critical detection of hex decode pipelines into interpreter execution
- bounded base64/hex payload deobfuscation with recursive decoded-text rescanning
  (size/depth-limited; decoded artifacts are never executed)
- decoded-payload rescanning coverage for Unicode threat and NFKC-drift signals
- base64url payload decoding support in bounded decoded-text rescanning
- critical detection of PowerShell encoded-command execution flags
- critical detection of PowerShell FromBase64String decode-to-IEX execution
- critical detection of PowerShell FromHexString decode-to-IEX execution
- critical detection of local base64 decode-to-exec/eval chains (Python/Node)
- critical detection of local hex decode-to-exec/eval chains (Python/Node)
- critical detection of Perl decode-to-eval chains (base64/hex)
- critical detection of Ruby decode-to-eval chains (base64/hex)
- critical detection of multi-line continuation execution chains
- critical detection of source/dot command-substitution execution chains
- critical detection of pipe-to-stdin source/dot execution chains
- decode output piped to `source`/`.` via stdin covers quoted and escaped-quoted stdin targets (including double-escaped-quoted variants; `/dev/stdin`, `/dev/fd/0`, `/proc/self/fd/0`, `/proc/thread-self/fd/0`, `/proc/<pid>/fd/0`, `/proc/$VAR/fd/0`, `/proc/${VAR}/fd/0`, `/proc/${VAR:-fallback}/fd/0`, `/proc/${VAR-fallback}/fd/0`, `/proc/${VAR:?msg}/fd/0`, `/proc/${VAR?msg}/fd/0`, `/proc/${VAR:=fallback}/fd/0`, `/proc/${VAR=fallback}/fd/0`, `/proc/${VAR:+fallback}/fd/0`, `/proc/${VAR+fallback}/fd/0`, `/proc/${VAR:?}/fd/0`, `/proc/${VAR?}/fd/0`, `/proc/${VAR:=}/fd/0`, `/proc/${VAR=}/fd/0`, `/proc/${VAR:+}/fd/0`, `/proc/${VAR+}/fd/0`, `/proc/$!/fd/0`, `/proc/$?/fd/0`, `/proc/$#/fd/0`, `/proc/$*/fd/0`, `/proc/$@/fd/0`, `/proc/$-/fd/0`, `/proc/$((expr))/fd/0`, `/proc/$[expr]/fd/0`, `/proc/$(cmd)/fd/0`, `/proc/$(cmd $(cmd))/fd/0`, `/proc/\`cmd\`/fd/0`, `/proc/\`cmd \\\`cmd\\\`\`/fd/0`, `/proc/$'expr'/fd/0`, `/proc/${!}/fd/0`, `/proc/${?}/fd/0`, `/proc/${#}/fd/0`, `/proc/${#VAR}/fd/0`, `/proc/${#1}/fd/0`, `/proc/${*}/fd/0`, `/proc/${@}/fd/0`, `/proc/${-}/fd/0`, `/proc/${!VAR}/fd/0`, `/proc/${!1}/fd/0`, `/proc/${VAR##pattern}/fd/0`, `/proc/${VAR%pattern}/fd/0`, `/proc/${VAR:offset}/fd/0`, `/proc/${VAR:offset:length}/fd/0`, `/proc/${VAR:${OFFSET}}/fd/0`, `/proc/${VAR:${OFFSET}:${LENGTH}}/fd/0`, `/proc/${VAR:offsetVar}/fd/0`, `/proc/${VAR:offsetVar:lengthVar}/fd/0`, `/proc/${VAR:$((expr))}/fd/0`, `/proc/${VAR:offset:$((expr))}/fd/0`, `/proc/${VAR: offset}/fd/0`, `/proc/${VAR: offset:length}/fd/0`, `/proc/${VAR:offset:-length}/fd/0`, `/proc/${VAR: -offset}/fd/0`, `/proc/${VAR: -offset:length}/fd/0`, `/proc/${VAR: -offset:-length}/fd/0`, `/proc/${VAR^^}/fd/0`, `/proc/${VAR,,}/fd/0`, `/proc/${VAR^}/fd/0`, `/proc/${VAR,}/fd/0`, `/proc/${VAR^^pattern}/fd/0`, `/proc/${VAR,,pattern}/fd/0`, `/proc/${VAR^pattern}/fd/0`, `/proc/${VAR,pattern}/fd/0`, `/proc/${VAR@Q}/fd/0`, `/proc/${VAR@E}/fd/0`, `/proc/${VAR@P}/fd/0`, `/proc/$1/fd/0`, `/proc/${1}/fd/0`, `/proc/${1:-fallback}/fd/0`, `/proc/${1-fallback}/fd/0`, `/proc/${1:?msg}/fd/0`, `/proc/${1?msg}/fd/0`, `/proc/${1:=fallback}/fd/0`, `/proc/${1=fallback}/fd/0`, `/proc/${1:+fallback}/fd/0`, `/proc/${1+fallback}/fd/0`, `/proc/${1:?}/fd/0`, `/proc/${1?}/fd/0`, `/proc/${1:=}/fd/0`, `/proc/${1=}/fd/0`, `/proc/${1:+}/fd/0`, `/proc/${1+}/fd/0`, `/proc/${1:offset}/fd/0`, `/proc/${1:offset:length}/fd/0`, `/proc/${1:${OFFSET}}/fd/0`, `/proc/${1:${OFFSET}:${LENGTH}}/fd/0`, `/proc/${1:offsetVar}/fd/0`, `/proc/${1:offsetVar:lengthVar}/fd/0`, `/proc/${1:$((expr))}/fd/0`, `/proc/${1:offset:$((expr))}/fd/0`, `/proc/${1: offset}/fd/0`, `/proc/${1: offset:length}/fd/0`, `/proc/${1:offset:-length}/fd/0`, `/proc/${1: -offset}/fd/0`, `/proc/${1: -offset:length}/fd/0`, `/proc/${1: -offset:-length}/fd/0`, `/proc/${1^^}/fd/0`, `/proc/${1,,}/fd/0`, `/proc/${1^}/fd/0`, `/proc/${1,}/fd/0`, `/proc/${1^^pattern}/fd/0`, `/proc/${1,,pattern}/fd/0`, `/proc/${1^pattern}/fd/0`, `/proc/${1,pattern}/fd/0`, `/proc/${1@A}/fd/0`, `/proc/${1@a}/fd/0`, `/proc/${1@Q}/fd/0`, `/proc/self/task/<tid>/fd/0`, `/proc/<pid>/task/<tid>/fd/0`, `/proc/$VAR/task/$VAR/fd/0`, `/proc/${VAR}/task/${VAR}/fd/0`, `/proc/${VAR:-fallback}/task/${VAR:-fallback}/fd/0`, `/proc/${VAR-$OTHER}/task/${VAR-$OTHER}/fd/0`, `/proc/${VAR:?msg}/task/${VAR?msg}/fd/0`, `/proc/${VAR:?}/task/${VAR?}/fd/0`, `/proc/${VAR:+fallback}/task/${VAR+fallback}/fd/0`, `/proc/${VAR:+}/task/${VAR+}/fd/0`, `/proc/$!/task/$?/fd/0`, `/proc/$#/task/${#}/fd/0`, `/proc/$*/task/${@}/fd/0`, `/proc/$-/task/${-}/fd/0`, `/proc/$((expr))/task/$((expr))/fd/0`, `/proc/$[expr]/task/$[expr]/fd/0`, `/proc/$(cmd)/task/$(cmd)/fd/0`, `/proc/$(cmd $(cmd))/task/$(cmd $(cmd))/fd/0`, `/proc/\`cmd\`/task/\`cmd\`/fd/0`, `/proc/\`cmd \\\`cmd\\\`\`/task/\`cmd \\\`cmd\\\`\`/fd/0`, `/proc/$'expr'/task/$'expr'/fd/0`, `/proc/${!}/task/${?}/fd/0`, `/proc/${*}/task/${@}/fd/0`, `/proc/${-}/task/$-/fd/0`, `/proc/${!VAR}/task/${!1}/fd/0`, `/proc/${VAR%%pattern}/task/${VAR#pattern}/fd/0`, `/proc/${#VAR}/task/${#1}/fd/0`, `/proc/${VAR:offset}/task/${VAR:offset:length}/fd/0`, `/proc/${VAR:${OFFSET}}/task/${VAR:${OFFSET}:${LENGTH}}/fd/0`, `/proc/${VAR:offsetVar}/task/${VAR:offsetVar:lengthVar}/fd/0`, `/proc/${VAR:$((expr))}/task/${VAR:$((expr))}/fd/0`, `/proc/${VAR:offset:$((expr))}/task/${VAR:offset:$((expr))}/fd/0`, `/proc/${VAR: offset}/task/${VAR: offset:length}/fd/0`, `/proc/${VAR:offset:-length}/task/${VAR:offset:-length}/fd/0`, `/proc/${VAR: -offset}/task/${VAR: -offset:length}/fd/0`, `/proc/${VAR: -offset:-length}/task/${VAR: -offset:-length}/fd/0`, `/proc/${VAR^^}/task/${VAR,,}/fd/0`, `/proc/${VAR^}/task/${VAR,}/fd/0`, `/proc/${VAR^^pattern}/task/${VAR,,pattern}/fd/0`, `/proc/${VAR^pattern}/task/${VAR,pattern}/fd/0`, `/proc/${VAR@Q}/task/${VAR@P}/fd/0`, `/proc/${VAR@E}/task/${VAR@Q}/fd/0`, `/proc/$1/task/$2/fd/0`, `/proc/${1}/task/${2}/fd/0`, `/proc/${1:-fallback}/task/${2:-fallback}/fd/0`, `/proc/${1-$2}/task/${3-$4}/fd/0`, `/proc/${1:?msg}/task/${2?msg}/fd/0`, `/proc/${1:?}/task/${2?}/fd/0`, `/proc/${1:+fallback}/task/${2+fallback}/fd/0`, `/proc/${1:+}/task/${2+}/fd/0`, `/proc/${1:offset}/task/${2:offset:length}/fd/0`, `/proc/${1:${OFFSET}}/task/${2:${OFFSET}:${LENGTH}}/fd/0`, `/proc/${1:offsetVar}/task/${2:offsetVar:lengthVar}/fd/0`, `/proc/${1:$((expr))}/task/${2:$((expr))}/fd/0`, `/proc/${1:offset:$((expr))}/task/${2:offset:$((expr))}/fd/0`, `/proc/${1: offset}/task/${2: offset:length}/fd/0`, `/proc/${1:offset:-length}/task/${2:offset:-length}/fd/0`, `/proc/${1: -offset}/task/${2: -offset:length}/fd/0`, `/proc/${1: -offset:-length}/task/${2: -offset:-length}/fd/0`, `/proc/${1^^}/task/${2,}/fd/0`, `/proc/${1^}/task/${2,,}/fd/0`, `/proc/${1^^pattern}/task/${2,pattern}/fd/0`, `/proc/${1^pattern}/task/${2,,pattern}/fd/0`, `/proc/${1@A}/task/${2@a}/fd/0`, `/proc/${1@Q}/task/${2@P}/fd/0`, `/proc/thread-self/task/<tid>/fd/0`, and `-`), optional or stacked `builtin`/`command` prefixes (including `command --` / `builtin --` forms, `command -p` / `builtin -p` forms with optional `--`, and attached `command--` / `command-p` / `builtin--` / `builtin-p` forms), equivalent stdin path spellings (for example `/dev//stdin`, repeated-slash `/dev//...` and `/proc//...` forms, and `fd/00...` forms including task-path `fd/00` variants), delimiter-terminated forms (including comma-terminated variants), and chains embedded in quoted command strings and backtick command strings
- nested-brace substring normalization also covers positional inner expansions (for example `${PPID:${1}}` and `${2:${3}:${4}}`) in `/proc/.../fd/...` and `/proc/.../task/.../fd/...` chains
- nested-brace substring normalization also covers defaulted inner expansions (for example `${PPID:${OFF:-1}}` and `${2:${TOFF:-1}:${TLEN:-1}}`) in `/proc/.../fd/...` and `/proc/.../task/.../fd/...` chains
- nested-brace substring normalization also covers inner fallback expressions that include another braced fallback (for example `${PPID:${OFF:-${ALT}}}` and `${2:${TOFF:-${TALT}}:${TLEN:-${LLEN}}}`) in `/proc/.../fd/...` and `/proc/.../task/.../fd/...` chains
- nested-brace substring normalization also covers deeper multi-level inner fallback nesting (for example `${PPID:${OFF:-${ALT:-${DEF}}}}`) in `/proc/.../fd/...` and `/proc/.../task/.../fd/...` chains
- nested-brace substring normalization also covers mixed nested/plain forms (for example `${PPID:${OFF}:1}` and `${2:${TOFF}:${TLEN:-1}}`) in `/proc/.../fd/...` and `/proc/.../task/.../fd/...` chains
- nested-brace substring normalization also covers plain-first nested-second forms (for example `${PPID:1:${LEN:-1}}` and `${2:2:${TLEN:-${TALT}}}`) in `/proc/.../fd/...` and `/proc/.../task/.../fd/...` chains
- critical detection of chmod-then-execute local artifact chains
- critical detection of secret-path reads combined with network exfiltration
- medium-severity detection of NFKC normalization text drift with normalized rescanning
- medium-severity detection of mixed-script filename patterns
- high-severity detection of ASCII/non-ASCII homoglyph path-name mixing
  (including compatibility-style Unicode glyphs after normalization)
- high-severity detection of password-protected archive instructions
- high-severity detection of shell/ssh/cron/launch-agent config writes
- high-severity detection of broad Bash wildcard tool permissions
- medium-severity detection of unknown/unclassified file types
- high-severity detection of remote script import patterns under unpinned runtime tooling
- unpinned-runtime pin checks that resolve npm/npx package-flag forms and
  ignore call-flag command values as package refs
- call-flag exclusion also covers attached short forms (for example
  `npx -cecho ...`)
- unpinned-runtime pin checks also resolve attached short package forms
  (for example `npx -p@scope/tool@...`)
- quoted runtime flag tokens are normalized before package/call interpretation
  for launcher pin checks
- aligned pnpm/yarn dlx checks with the same package-flag and call-flag handling model
- hardened go-run target extraction for split-value flags and separator forms
- hardened go-run detection for pre-subcommand `go -C <dir> run ...` form
- quoted go-run subcommand/flag token normalization for go-run target
  extraction (for example `go "run" ...` and `go "-C" <dir> "run" ...`)
- unpinned-runtime detection for `deno run/x` npm specifier execution paths
- unpinned-runtime detection for `deno run/x` jsr specifier execution paths
- unpinned-runtime detection for `deno create` template package execution paths
  (including `--npm`/`--jsr` unprefixed package modes)
- unpinned-runtime detection for `deno init` package-generation execution paths
  (including `--npm`/`--jsr` package modes)
- unpinned-runtime detection for `deno serve` runtime specifier execution paths
- unpinned-runtime detection for `deno install -g/--global` runtime specifier execution paths
- unpinned-runtime detection for remote `http(s)` Deno target execution in
  `deno run/x/serve`, `deno install -g/--global`, and run-omitted
  `deno <url>` forms
- deno `--package` runtime checks also evaluate target specifiers for unpinned refs
- deno `-p<specifier>` attached short package forms are extracted for pin checks
- deno runtime target extraction handles optional-value flags (`--reload`/`-r`,
  `--frozen`, `--vendor`, and `--node-modules-dir`) without skipping unpinned
  specifier targets
- for `deno x`, split `--install-alias` forms are interpreted before target
  extraction so later runtime specifier targets remain pin-checked
- quoted Deno launcher/subcommand/flag tokens are normalized before target
  extraction so quoted `deno`/`run`/`install` forms remain pin-checked
- backslash-escaped quoted Deno launcher/subcommand/flag tokens (for example
  `\"deno\"` / `\"run\"`) are normalized before target extraction so escaped
  quote forms remain pin-checked
- deno runtime checks also evaluate `deno` tokens that appear later in a line
  (for example prefixed command strings like `echo && deno run ...`) so
  embedded forms remain pin-checked
- control-operator-adjacent launcher/runtime tokens (for example `&&deno`,
  `||npx`, and `!deno`) are normalized before runtime/launcher evaluation so
  glued forms remain pin-checked
- separator-adjacent launcher/runtime tokens embedded in the same field (for
  example `echo;deno`, `echo;!deno`, and `echo;npx`) are normalized before
  runtime/launcher evaluation so non-whitespace separator forms remain
  pin-checked
- corepack-wrapped compact package-manager/subcommand forms in the same field
  (for example `corepack pnpm;dlx ...` and `corepack npm;exec ...`) are
  decomposed before runtime/launcher evaluation so those forms remain
  pin-checked
- command-substitution-prefixed launcher/runtime tokens (for example `$(deno`
  / `$(npx` / `$(corepack`) are normalized before runtime/launcher evaluation
  so substitution forms remain pin-checked
- deno split `--node-modules-linker` forms are interpreted before target
  extraction so later runtime specifier targets remain pin-checked
- deno split `--minimum-dependency-age` forms are interpreted before target
  extraction so later runtime specifier targets remain pin-checked
- deno split `--tunnel`/`-t` forms are interpreted before target extraction so
  later runtime specifier targets remain pin-checked
- deno `serve` split `--host`/`--port` forms are interpreted before target
  extraction so later runtime specifier targets remain pin-checked
- deno `install -g/--global` split `--name`/`-n`, `--root`, and
  `--entrypoint`/`-e` forms are interpreted before target extraction so later
  runtime specifier targets remain pin-checked
- deno split `--lock` forms are interpreted before target extraction so later
  runtime specifier targets remain pin-checked
- deno split `--cpu-prof-dir`/`--cpu-prof-interval`/`--cpu-prof-name` forms
  are interpreted before target extraction so later runtime specifier targets
  remain pin-checked
- deno `--reload`/`-r` split blocklist values are interpreted before target
  extraction so later unpinned runtime targets are still detected
- deno split `--frozen` boolean forms are interpreted before target extraction
  so later runtime specifier targets remain pin-checked
- deno split `--allow-scripts` package-value forms are interpreted
  conservatively before target extraction so later runtime specifier targets are
  still evaluated for pinning
- deno split `--allow-import` host/url allowlist forms (including `-I`) are
  interpreted before target extraction so later runtime specifier targets
  remain pin-checked
- deno split permission forms for `--allow-read`/`--allow-net`/`--allow-env`
  (and `-R`/`-N`/`-E`) are interpreted before target extraction so later
  runtime specifier targets remain pin-checked
- deno split permission forms for `--allow-write`/`--allow-run`/`--allow-ffi`
  (and `-W` for write) are interpreted before target extraction so later
  runtime specifier targets remain pin-checked
- deno split `--allow-sys` forms (including `-S`) are interpreted before target
  extraction so later runtime specifier targets remain pin-checked, and
  `--allow-hrtime` forms keep subsequent target evaluation intact
- deno split `--deny-*` permission forms (`read|write|net|env|run|ffi|import|sys`)
  are interpreted before target extraction so later runtime specifier targets
  remain pin-checked
- deno split inspector-address forms (`--inspect`, `--inspect-brk`,
  `--inspect-wait`) and split `--ext` forms are interpreted before target
  extraction so later runtime specifier targets remain pin-checked
- deno split `--watch`/`--watch-exclude`/`--watch-hmr` forms and split
  `--env-file`/`--preload`/`--require` forms (including the `--import` preload
  alias) are interpreted before target extraction so later runtime specifier
  targets remain pin-checked
- deno split `--conditions` forms are interpreted before target extraction so
  later runtime specifier targets remain pin-checked
- deno split `--strace-ops`/`--strace-filter` forms are interpreted before
  target extraction so later runtime specifier targets remain pin-checked
- deno split `--coverage` forms and split `--v8-flags` forms are interpreted
  before target extraction so later runtime specifier targets remain pin-checked
- deno split `--check`/`--no-check` forms and split `--log-level` forms
  (including `-L`) are interpreted before target extraction so later runtime
  specifier targets remain pin-checked
- dependency manifest scanning coverage for `package.json`, `pyproject.toml`,
  `requirements.txt`, `uv.lock`, `go.mod`, `Gemfile`, `deno.json`, and
  `deno.jsonc` as first-class scan inputs

This roadmap section below remains forward-looking for gaps and future phases.

## Design Principles

- Fail closed for third-party skills.
- Treat `SKILL.md` natural-language instructions as executable influence.
- Treat invisible Unicode as a blocking security signal.
- Never install directly from an archive, branch, tag, or release asset.
- Separate `fetch`, `inspect`, `install`, and `update`.
- Pin provenance with commit SHAs and file digests.
- Make reports human-readable, machine-readable, and safe to show to another
  tool.

## Phase 0: Project Skeleton

Goal: establish the CLI and package boundaries without pretending the scanner is
complete.

- Create Go module and `cmd/gokui`.
- Add command framework for `inspect`, `install`, `update`, and `lock verify`.
- Add package structure:
  - `internal/source`
  - `internal/materialize`
  - `internal/skill`
  - `internal/scan`
  - `internal/policy`
  - `internal/install`
  - `internal/report`
- Add golden test fixtures for clean, suspicious, and malicious-looking skills.
- Add JSON report schema draft.
- Add CI for tests, formatting, and static checks.

Exit criteria:

- `gokui inspect ./fixtures/clean-skill --format json` emits a stable report.
- The CLI clearly labels the project as pre-release.

## Phase 1: Local Inspect MVP

Goal: inspect local directories and local archives without network access.

- Validate `SKILL.md` existence and root placement.
- Parse frontmatter with strict YAML rules:
  - reject duplicate keys
  - reject anchors and aliases
  - reject merge keys
  - reject custom tags
- Validate `name`:
  - ASCII lowercase letters, digits, and hyphens only
  - no leading or trailing hyphen
  - no repeated hyphen
  - must match parent directory
  - maximum 64 characters
- Validate `description`:
  - required
  - 1 to 1024 characters
  - no URLs
  - no code fences
  - no shell/tool execution
  - no prompt override language
- Add safe zip and tar materialization into quarantine:
  - reject absolute paths
  - reject `..`
  - reject path escape after canonicalization
  - reject symlinks, hardlinks, devices, and FIFOs
  - enforce file count and size limits
- Add Unicode scanner for all text files:
  - Unicode Tags
  - bidi controls
  - zero-width characters
  - variation selectors
  - ANSI/OSC escapes
  - C0/C1 controls except tab and line endings
  - NFKC-change warnings
  - mixed-script filename warnings
- Add human and JSON reports.

Exit criteria:

- Invisible Unicode in `SKILL.md` is rejected by default.
- Archive path traversal and symlink fixtures are rejected before extraction.
- Reports render dangerous code points only as escaped text.

## Phase 2: Markdown and Instruction Scanner

Goal: catch the highest-risk prompt and social-engineering patterns before a
skill reaches an agent.

- Scan `SKILL.md`, `references/**/*.md`, and README-like files.
- Add category-based detectors:
  - prompt override
  - stealth
  - tool execution
  - secret access
  - exfiltration
  - fake prerequisites
  - setup/install command induction
  - obfuscation terms
  - raw HTML and link spoofing
- Add URL extraction and URL risk classification:
  - shorteners
  - paste sites
  - raw IP hosts
  - release assets
  - password-protected archive language
  - remote images
- Add normalized keyword scan after Unicode normalization.
- Add bounded fuzzy matching for common prompt-injection phrases.

Exit criteria:

- A fake prerequisite that asks the user to download and run an external binary
  is rejected.
- A `description` that broadens activation to all tasks is rejected or high
  severity.
- Raw Markdown findings include file, line, excerpt, reason, and neutralized
  context.

## Phase 3: Script, Command, and Deobfuscation Scanner

Goal: identify common execution and exfiltration paths without running bundled
code.

- Add shell parsing with `mvdan.cc/sh/v3/syntax`.
- Add lexical scanners for:
  - Python
  - JavaScript and TypeScript
  - PowerShell
  - batch files
  - Ruby
  - Go
  - shebang files
  - executable-bit files
- Detect critical command/dataflow patterns:
  - network fetch to shell/interpreter/eval
  - base64 or hex decode to shell/interpreter/eval
  - `EncodedCommand`
  - `chmod +x` followed by local execution
  - suspicious writes to shell rc, cron, launch agents, or service paths
  - secret reads combined with network sends
- Add dependency and manifest scanning:
  - `package.json`
  - `pyproject.toml`
  - `requirements.txt`
  - `uv.lock`
  - `go.mod`
  - `Gemfile`
  - `deno.json`
  - `deno.jsonc`
- Flag unpinned runtime tools:
  - `npx foo`
  - `uvx foo`
  - `bunx foo`
  - `pnpm dlx foo`
  - `yarn dlx foo`
  - `npm exec foo`
  - `go run github.com/org/tool` (no `@version`)
  - `go run github.com/org/tool@main` (floating branch/tag refs)
  - `go run ...@latest`
  - remote script imports
- Add bounded deobfuscation:
  - base64-like strings of 40+ characters
  - hex strings of 32+ bytes
  - maximum recursion depth 3
  - maximum decoded artifact size 1 MB
  - decoded artifacts are rescanned, never executed

Exit criteria:

- `curl | sh`, `wget | bash`, and equivalent AST forms are critical.
- `base64 -d | sh` and decoded hidden command fixtures are critical.
- Unpinned runtime tools are high severity under strict policy.

## Phase 4: Policy Engine and Install MVP

Goal: make decisions predictable and install only policy-passed artifacts.

- Implement built-in profiles:
  - `strict`
  - `team`
  - `research`
- Add user policy loading from `~/.config/gokui/policy.toml`.
- Aggregate findings into decisions:
  - critical: reject
  - high: reject by default
  - medium: warn by default
  - low: inform
- Add `--format human|json`.
- Add `--profile`.
- Add `--override <finding-id>` for explicit high-severity exceptions where the
  selected profile allows override.
- Implement `--target codex` and `--target custom:/path`.
- Install atomically:
  - copy to staging
  - normalize permissions
  - drop executable bits by default
  - write `.gokui-report.json`
  - write `gokui.lock`
  - rename into destination
- Reject skill name collisions unless lockfile provenance matches.

Exit criteria:

- `gokui install ./skill --target codex --profile strict` refuses critical or
  high findings.
- Installed skills include a lockfile and report.
- Reinstalling a same-name skill from a different source is rejected.

## Phase 5: Source Resolver and Update Flow

Goal: fetch remote skills while preserving immutability and reviewable diffs.

- Add GitHub source syntax:
  - `github:org/repo//path/to/skill@commit`
  - branch and tag accepted for inspect only with warning
- Resolve branch and tag refs to commit SHAs.
- Require commit-pinned sources for install.
- Compute archive and root digests.
- Add `gokui fetch`.
- Add `gokui update --dry-run`:
  - compare old and new file digests
  - show added/removed/changed files
  - show risk delta
  - show new URLs
  - show new executable files
  - show new invisible Unicode findings
- Add `gokui lock verify`:
  - recompute file digests
  - detect local drift
  - verify source identity

Exit criteria:

- Floating refs cannot be installed silently.
- Updates are diff-first and require a fresh policy pass.
- Lock verification detects local modifications.

## Phase 6: Report Formats and Ecosystem Use

Goal: make gokui useful in CI and team review.

- Expand SARIF output coverage beyond `inspect`.
- Expand compact summary output coverage for CI logs.
- Expand `gokui vet` ergonomics for skill-author CI workflows.
- Add baseline support for repositories with many skills.
- Add rule documentation with examples and remediation notes.
- Add machine-readable stable finding IDs.
- Add severity override audit trail.

Exit criteria:

- Skill authors can run `gokui vet ./skills/my-skill` in CI.
- Security findings can be surfaced in GitHub code scanning through SARIF.

## Phase 7: Hardening and Future Work

Goal: reduce bypasses and improve signal without moving trust into an LLM.

- Improve fuzzy matching and typoglycemia detection.
- Improve mixed-script and confusable detection using Unicode security data.
- Expand neutralized structured-review exports for optional human or
  AI-assisted review.
- Add trusted publisher or signature support.
- Add organization policy bundles.
- Expand repository-level `.gokui-policy.toml` usage for CI and multi-skill repositories.
- Expand differential risk scoring for updates with calibrated policy profiles.
- Add signed report support.
- Evaluate additional targets after Codex and custom target behavior is stable.

Exit criteria:

- Optional AI-assisted review consumes only neutralized structured data.
- Signed provenance and reports can be verified independently.
- Team policy usage is documented and tested.

## Initial Severity Rules

Critical findings reject in all profiles:

| Rule | Condition |
| --- | --- |
| `UNICODE_TAG_IN_INSTRUCTIONS` | Unicode Tags in `SKILL.md` or references |
| `BIDI_CONTROL_IN_TEXT` | bidi override or isolate controls in text |
| `CURL_PIPE_SHELL` | network fetch output reaches shell, interpreter, or eval |
| `BASE64_PIPE_EXEC` | decoded payload reaches shell, interpreter, or eval |
| `HEX_PIPE_EXEC` | hex-decoded payload reaches shell, interpreter, or eval |
| `ENCODED_COMMAND_EXEC` | PowerShell encoded-command execution flag detected |
| `CHMOD_EXEC_CHAIN` | chmod +x followed by execution of the same local artifact |
| `ARCHIVE_PATH_ESCAPE` | archive entry resolves outside quarantine |
| `SYMLINK_IN_ARCHIVE` | archive contains symlink or hardlink |
| `SECRET_EXFIL` | secret read combined with network send |
| `FAKE_PREREQ_EXECUTION` | prerequisite language plus download/run instruction |
| `DESCRIPTION_TOOL_INJECTION` | description includes tool execution or override instruction |

High findings reject under `strict`:

| Rule | Condition |
| --- | --- |
| `UNPINNED_RUNTIME_TOOL` | `npx`, `uvx`, `bunx`, `pnpm/yarn dlx`, `npm exec`, `go run`, corepack-wrapped launchers, or similar floating execution |
| `EXTERNAL_BINARY_DOWNLOAD` | release asset or binary download instruction |
| `PASSWORD_PROTECTED_ARCHIVE` | password-protected archive instruction |
| `RAW_IP_URL` | URL host is an IP address |
| `ALLOWED_TOOLS_BASH_WILDCARD` | broad `Bash` or wildcard tool permission |
| `WRITES_HOME_CONFIG` | writes to shell rc, ssh, cron, launch agents, or similar |
| `CONFUSABLE_FILENAME` | filename or directory name mixes ASCII with confusable non-ASCII homoglyphs (including compatibility-style normalized glyphs and dot-like separators) |

Medium findings warn under `strict`:

| Rule | Condition |
| --- | --- |
| `URL_SHORTENER` | shortener URL |
| `PASTE_SITE_URL` | paste-site URL |
| `RELEASE_ASSET_URL` | GitHub release asset URL |
| `REMOTE_IMAGE_URL` | remote Markdown image URL |
| `RAW_HTML_MARKUP` | raw HTML markup in markdown |
| `LARGE_TEXT_FILE` | unusually large text file for scan |
| `UNKNOWN_FILE_TYPE` | binary or unclassified file |
| `NFKC_CHANGES_TEXT` | Unicode normalization changes text |
| `MIXED_SCRIPT_FILENAME` | filename uses mixed scripts |

## MVP Definition

The first usable MVP is complete when gokui can:

- inspect local directories, zip files, tar files, and GitHub commit-pinned
  sources
- reject unsafe archive entries before materialization
- validate strict skill frontmatter
- reject invisible Unicode in instruction files
- detect common prompt injection and fake prerequisite patterns
- detect dangerous shell execution patterns
- decode bounded base64 and hex payloads for rescanning
- enforce `strict` policy
- install to Codex and custom targets atomically
- write `gokui.lock` and `.gokui-report.json`
- verify installed lockfiles
- produce human and JSON reports

Anything beyond that should not block the MVP unless it closes a direct bypass
in one of the listed guarantees.
