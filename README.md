# gokui

gokui is a quarantine gate for Agent Skill bundles.

It is not designed as a safe package manager that makes third-party skills
trustworthy. Its job is narrower and stricter: before a local agent reads
someone else's `SKILL.md`, scripts, references, or assets, gokui fetches the
bundle into quarantine, inspects it as untrusted input, records provenance, and
only then allows installation under a policy.

Agent Skills are powerful because an agent can read `SKILL.md` as instructions,
not just documentation. That means the risky artifact is not only executable
code in `scripts/`; natural-language Markdown, descriptions, setup steps,
hidden Unicode, links, and fake prerequisites can also affect what the agent
does. gokui treats all of those layers as security-relevant.

## Status

gokui is pre-release software under active hardening. Current commands are
implemented with stable automation contracts, while security coverage and policy
depth continue to expand. `inspect` now performs pre-release structural validation and
basic markdown threat scanning, emits draft human/JSON reports, and supports
`--format sarif` for CI/code-scanning pipelines. Decisions remain
`PASS`/`REJECTED`. In JSON mode, fatal inspect failures emit
machine-readable top-level `error_code` for automation. In SARIF mode, fatal
inspect and `vet` failures emit a single structured error result. For GitHub sources, floating refs remain
inspect-only pre-release stubs, while commit-pinned refs are fetched and
scanned.
`fetch`, `inspect`, `vet`, `install`, `update`, and `lock verify` also support `--format compact` for single-line CI summaries.
`inspect` and `vet` also support `--format review-json`, a neutralized structured
export for optional human/AI-assisted review pipelines.
`fetch` also supports `--format sarif` for quarantine provenance export in CI.
`install` also supports `--format sarif` for policy findings export in CI.
In SARIF mode, fatal install failures emit a single structured error result.
`install` now supports local-dir/zip/tar sources with built-in profiles
`strict|team|research`. `strict` and `team` reject high/critical findings;
`research` rejects critical findings. It installs atomically to `--target codex`
or `--target custom:/path`, writes `.gokui-report.json` and `gokui.lock`, allows
idempotent reinstall only when provenance matches and existing lock structure is valid, and rejects same-name
different-provenance installs. It also supports commit-pinned GitHub sources
(`github:owner/repo//path@<sha>`) via safe tarball materialization. In JSON
mode, rejected installs set report `error_code=INSTALL_POLICY_REJECTED`, and
fatal errors emit a machine-readable error envelope with top-level `error_code`.
Idempotent reuse also verifies installed-file digests/root hash (and GitHub
source metadata for GitHub-origin installs), and install-report integrity,
rejecting drifted installations.
When `--profile` is omitted, install can load `default_profile` from
`~/.config/gokui/policy.toml` (or `GOKUI_POLICY_PATH`).
Install and update can also load the nearest ancestor repository policy file
named `.gokui-policy.toml` for `local-dir` sources; when found, it is used in
preference to user policy for that skill evaluation.
`policy.toml` can also control override behavior via `[overrides]`:
`enabled = false` disables all CLI overrides, and `allowed_rule_ids = [...]`
restricts overrides to an explicit allowlist.
Profile-specific reject thresholds can be set via
`[profiles.<name>].reject_severities = ["critical", ...]`.
`vet` also resolves effective profile and reject severities from policy when
`--profile` is omitted, using user policy by default and nearest-ancestor
repository policy (`.gokui-policy.toml`) in preference for `local-dir`
sources.
`install --override RULE_ID` can explicitly downgrade matching high-severity
findings for decision calculation, and records `severity_overrides` audit
entries in install report/lock metadata.
Install source copy now enforces strict per-file byte limits without writing
overflow bytes and removes partial destination files on overflow/error.
Install source-copy and digest roots now reject symlink or non-directory input
paths before traversal.
Install/update target roots and lock-verify input paths reject symlink path components.
Lock/source-metadata/install-report file reads also reject symlink path components,
and require regular files (no directory/device/FIFO/socket paths).
Source metadata writes also reject symlink path components and non-regular targets.
Install target entries also reject symlink path components.
`lock verify` now validates installed files against `gokui.lock`, checks source
field consistency (including strict GitHub source syntax and commit pinning),
validates lock/report structural integrity, validates GitHub source metadata
integrity, enforces canonical lowercase lock digests (`root_sha256` and per-file
`sha256`), enforces canonical `severity_overrides` audit entry fields
(`rule_id`/`severity`/`source`/`applied_at`, with allowed `source` values
`cli-override|policy-file`), enforces exact install-report schema version,
validates non-negative findings summary counters,
reports drift, and emits per-check `code` fields in JSON output for
automation (including missing/changed/unexpected file drift details). On fatal
verify errors, JSON output includes top-level `error_code`, and SARIF output
emits a single structured error result. It also supports `--format sarif` for
drift/check export in CI pipelines.
`update --dry-run` now re-evaluates installed skills from lockfile source
provenance for local-dir/zip/tar sources, reports added/removed/changed files,
risk deltas, and new URL/executable signals. For GitHub sources, commit-pinned
refs are evaluated and floating refs are rejected. Lockfile source fields are
also validated strictly (kind/input/type consistency + canonical lowercase form
without surrounding whitespace), lock policy fields are validated for
canonical form (`profile`/`decision`), and lock skill snapshot digests/paths
are validated before evaluation. Lock envelope integrity (`schema`, `name`,
`installed_at`, `severity_overrides`, and non-negative findings counters) is also validated before evaluating
source diffs. When `.gokui-report.json` exists in the installed skill, update
also requires it to match lock baseline fields before differential evaluation.
JSON output now emits
stable
skill-item keys for automation-friendly parsing, including `error_code` for
status-aware automation. Update target entries and URL/executable scan inputs
must not contain symlink path entries, and URL/executable scan roots must be
non-symlink directories.
For `github-source`, lock input must also be canonical
(`github:owner/repo//clean/path@ref`) after parser normalization.
The same canonical requirement applies to `.gokui-source.json`
`source_input` during metadata validation. Source metadata also requires
canonical lowercase/no-whitespace `resolved_ref` and `skill_root_sha256`.
Update policy decisions also honor profile-specific `reject_severities`
configured via user policy (`policy.toml`) or repository policy
(`.gokui-policy.toml`) for `local-dir` sources.
It also supports `--format sarif` for CI/code-scanning ingestion.
In SARIF mode, fatal update failures emit a single structured error result.
URL risk classification now flags shortener hosts and raw-IP URLs during scan.
It also flags paste-site URLs, GitHub release asset URLs, and remote image
URLs in markdown content for review.
Markdown raw HTML markup is now flagged as a medium-severity finding.
Markdown links with host-mismatched display URL/target URL are flagged as high
severity link-spoofing findings.
Prompt-override language detection now includes bounded fuzzy/typoglycemia
matching for common injection phrases.
PowerShell `-EncodedCommand` / `-enc` execution flags are now flagged as
critical findings.
`chmod +x` followed by execution of the same local artifact is now flagged as
critical.
Writes to shell rc, SSH config, cron, or launch-agent configuration paths are
now flagged as high severity.
Secret-path access combined with network exfiltration commands is now flagged
as critical.
Broad Bash wildcard tool permissions are now flagged as high severity.
Unknown/unclassified file types are now flagged as medium severity for manual
review.
Remote script import patterns (for example `source <(curl ...)`, `. <(curl ...)`, and
`deno run https://...`) plus floating runtime launchers (for example `bunx`,
`pnpm dlx`, `yarn dlx`, and `npm exec`, including `corepack`-wrapped forms)
are now flagged under
`UNPINNED_RUNTIME_TOOL`.
Bounded base64/hex payload deobfuscation now rescans decoded text artifacts
(depth-limited and size-limited, never executed) to catch hidden execution
chains.
Unicode Tags, bidi controls, variation selectors, and ANSI/OSC escapes in
scanned text are now flagged as critical. Zero-width and disallowed C0/C1
control characters are also flagged as critical findings.
Lines whose Unicode compatibility normalization changes instruction text are now
flagged as medium-severity `NFKC_CHANGES_TEXT` findings, and normalized text is
rescanned to catch fullwidth compatibility evasion patterns.
Mixed-script filename patterns that can mimic trusted names are now flagged as
medium severity findings.
ASCII/non-ASCII homoglyph filename mixing (for example Cyrillic/Greek lookalikes)
is now flagged as high severity `CONFUSABLE_FILENAME`.
Password-protected archive instructions are now flagged as high severity.
JSON output contracts are now stability-tested across `inspect`, `fetch`,
`install`, `update`, `lock verify`, and install metadata files.
CI now includes a dedicated SARIF smoke job that runs `inspect --format sarif`
against a rejected fixture and uploads the SARIF artifact for review.
`fetch` now supports commit-pinned GitHub sources and materializes them into a
quarantine output root via `--out`, and records `.gokui-source.json`
provenance metadata. In JSON mode, fetch failures return `error_code` for
automation. In SARIF mode, fatal fetch failures emit a single error result with
`ruleId` derived from `rule_id` (if available) or `error_code`. Fetch output
roots and output entries must not be symlink paths.
GitHub archive downloads also enforce redirect safety constraints (HTTPS only,
same host and port, and no redirect userinfo) plus response header validation
for expected archive content types and content encoding. Streamed size limits
are enforced without writing overflow bytes, and partial archive files are
removed on failure. Redirect following is also capped to a strict maximum.
GitHub source syntax is now strictly validated as
`github:owner/repo//path/to/skill@ref`; `install` requires commit-pinned refs
for GitHub sources and rejects floating refs. `install` and `update` validate
fetched source metadata for GitHub-origin skills.
Parser bounds are also enforced for overall source length and owner/repo/path/ref
segment lengths.
Local directory inspect already enforces that `SKILL.md` exists at the skill
root, rejects symlinked source paths/components or symlinked `SKILL.md`, and
requires `SKILL.md` to be a regular file (not a directory/device/FIFO/socket).
Inspect/update scan walkers now reject symlinked or non-directory scan roots
and reject non-regular files before reading.
It also validates strict YAML frontmatter rules (no duplicate keys, anchors,
aliases, merge keys, or custom tags), requires a valid `name` that matches the
directory name, and enforces safety-oriented `description` checks.
For local zip/tar inputs, inspect now performs safe archive materialization
checks (path escape, symlink/hardlink/special entry rejection, and size/count
limits) before applying skill validation.

The intended first release focuses on local inspection and strict Codex-targeted
installation:

```sh
gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir>
gokui inspect <local-dir|zip|github-source>
gokui vet <local-dir|zip|tar>
gokui install <source> --target codex --profile strict
gokui update --dry-run
gokui lock verify
```

Current pre-release CLI syntax:

```sh
gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir> [--format human|json|sarif|compact]
gokui inspect <local-dir|zip|github-source> [--format human|json|sarif|compact|review-json]
gokui vet <local-dir|zip|tar> [--profile strict|team|research] [--format human|json|sarif|compact|review-json]
gokui install <source> --target codex --profile strict|team|research [--format human|json|sarif|compact] [--override RULE_ID ...]
gokui update --dry-run [--target codex|custom:/path] [--format human|json|sarif|compact]
gokui lock verify [path] [--format human|json|sarif|compact]
```

Release readiness gate:

```sh
# Includes fmt/lint/typecheck/deadcode/coverage/test/test-race/build,
# inspect-sarif smoke generation, and govulncheck
make release-check

# Offline fallback when vulnerability DB access is unavailable
make release-check RELEASE_CHECK_VULN=0

# Equivalent shorthand
make release-check-offline

# Generate inspect SARIF fixture artifact and assert expected reject signal
make inspect-sarif

# Create a timestamped release evidence file from template
make release-evidence

# Run offline release gate and auto-generate evidence + logs
make release-evidence-offline

# Run offline gate + vuln check and auto-generate evidence + logs
make release-evidence-online
```

CI is configured to resolve the latest available patch release for the selected
Go minor version (`actions/setup-go` with `check-latest: true`).
`make vuln` also defaults to a minimum patched toolchain via
`VULN_GOTOOLCHAIN=go1.26.3+auto` (override on demand).

Release execution checklist: [RELEASE.md](RELEASE.md)

## Threat Model

gokui assumes that a skill bundle from another person or repository is
untrusted until proven policy-compliant.

The main risks are:

- Prompt injection in `SKILL.md`, `description`, or reference Markdown.
- Invisible Unicode instructions that humans do not see during review.
- Shell, Python, JavaScript, PowerShell, or one-off runtime commands that fetch
  and execute remote code.
- Fake prerequisites that ask users or agents to download and run a "required"
  helper binary.
- Archive extraction attacks such as path traversal, symlinks, hardlinks, or
  special files.
- Skill name squatting, shadowing, and overbroad activation descriptions.
- Supply-chain drift from floating refs such as branches, tags, releases, or
  `@latest` runtime tools.

gokui does not claim that a passed skill is safe. A passed skill means the
artifact was inspected, matched a configured policy, and has recorded
provenance. Runtime sandboxing, tool permissions, network controls, and human
confirmation remain separate layers.

## Core Workflow

gokui separates fetching, inspection, and installation.

```sh
gokui fetch github:org/repo//skills/pdf-helper@8f3c2d1a4b5c6d7e8f901234567890abcdef1234 --out .gokui/quarantine
gokui inspect .gokui/quarantine/pdf-helper --format human
gokui install .gokui/quarantine/pdf-helper --target codex --profile strict --format human
gokui update --target codex --dry-run --format human
```

The intended flow is:

1. Fetch into a quarantine directory.
2. Materialize archives safely without writing outside quarantine.
3. Validate the skill structure and frontmatter.
4. Scan text, Markdown, scripts, dependencies, URLs, and decoded payloads.
5. Make a policy decision.
6. Install atomically with normalized permissions, a lockfile, and a report.

## Automation Error Codes

For machine integration, JSON outputs use stable uppercase `error_code` values.
Fatal JSON error envelopes may also include optional `rule_id` when a
rule-prefixed validation error is available.

### inspect (`--format json`, fatal errors)

| error_code | Meaning |
| --- | --- |
| `INSPECT_ARGS_INVALID` | CLI argument parse/validation failed |
| `INSPECT_SOURCE_NOT_FOUND` | source path does not exist |
| `INSPECT_SOURCE_INVALID` | GitHub source syntax is invalid |
| `INSPECT_SOURCE_PREPARE_FAILED` | source materialization/structure validation failed |
| `INSPECT_SCAN_FAILED` | scan phase failed |
| `INSPECT_POLICY_LOAD_FAILED` | policy file load/parse/validation failed |
| `INSPECT_FAILED` | fallback when inspect fatal error classification is unavailable |

When available, inspect JSON fatal errors also include optional `rule_id`
derived from rule-prefixed validation messages (for example
`ARCHIVE_PATH_ESCAPE`, `SYMLINK_IN_ARCHIVE`, `DESCRIPTION_TOOL_INJECTION`).

### fetch (`--format json`, fatal errors)

| error_code | Meaning |
| --- | --- |
| `FETCH_ARGS_INVALID` | CLI argument parse/validation failed |
| `FETCH_SOURCE_UNSUPPORTED` | source type is unsupported |
| `FETCH_SOURCE_INVALID` | GitHub source syntax is invalid |
| `FETCH_SOURCE_REF_NOT_PINNED` | GitHub ref is not commit-pinned |
| `FETCH_SOURCE_DOWNLOAD_FAILED` | download/materialization failed |
| `FETCH_SKILL_INVALID` | fetched skill metadata/frontmatter is invalid |
| `FETCH_OUTPUT_PREPARE_FAILED` | output directory preparation failed |
| `FETCH_COPY_FAILED` | staging/copy step failed |
| `FETCH_DIGEST_FAILED` | digest generation failed |
| `FETCH_SOURCE_METADATA_WRITE_FAILED` | source metadata write failed |
| `FETCH_FAILED` | fallback when fetch fatal error classification is unavailable |

When available, fetch JSON fatal errors also include optional `rule_id`
derived from rule-prefixed source/materialization validation errors.
Install JSON reports and generated lockfiles also include
`severity_overrides` as an audit trail field (currently empty in strict mode
unless explicit overrides are introduced in future policy phases).

### install (`--format json`)

Rejected policy decision:
- `INSTALL_POLICY_REJECTED` (report `decision=REJECTED`, exit code `2`)

Fatal errors:

| error_code | Meaning |
| --- | --- |
| `INSTALL_ARGS_INVALID` | CLI argument parse/validation failed |
| `INSTALL_PROFILE_UNSUPPORTED` | unsupported profile selected |
| `INSTALL_POLICY_LOAD_FAILED` | user policy file load/parse/validation failed |
| `INSTALL_OVERRIDE_NOT_ALLOWED` | requested override is disallowed by profile/policy |
| `INSTALL_SOURCE_NOT_FOUND` | non-GitHub source path not found |
| `INSTALL_SOURCE_PREPARE_FAILED` | source preparation/materialization failed |
| `INSTALL_EVALUATION_FAILED` | scan/evaluation phase failed |
| `INSTALL_SOURCE_METADATA_INVALID` | source metadata validation failed |
| `INSTALL_TARGET_INVALID` | target spec is invalid |
| `INSTALL_TARGET_PREPARE_FAILED` | target root preparation failed |
| `INSTALL_WRITE_FAILED` | install write/staging/finalize failed |
| `INSTALL_FAILED` | fallback when install fatal error classification is unavailable |

When available, install JSON fatal errors also include optional `rule_id`
derived from rule-prefixed source/materialization validation errors.

### lock verify (`--format json`, fatal errors)

| error_code | Meaning |
| --- | --- |
| `LOCK_VERIFY_ARGS_INVALID` | CLI argument parse/validation failed |
| `LOCKFILE_READ_FAILED` | lockfile read failed |
| `LOCKFILE_INVALID_JSON` | lockfile JSON parse failed |
| `FILE_DIGEST_BUILD_FAILED` | digest build failed |
| `LOCK_VERIFY_FAILED` | other verify failure |

When available, lock verify JSON fatal errors also include optional `rule_id`
derived from rule-prefixed lock/source validation messages.

Per-check `checks[].code` values:
- `LOCK_SCHEMA`
- `SKILL_NAME`
- `LOCK_STRUCTURE`
- `LOCK_SOURCE`
- `SOURCE_METADATA`
- `INSTALL_REPORT`
- `FILE_DIGESTS`
- `ROOT_HASH`

### update (`--format json`, per-skill `skills[].error_code`)

| error_code | Meaning |
| --- | --- |
| `UP_TO_DATE` | no source or risk delta |
| `SOURCE_CHANGED` | source drift detected |
| `POLICY_REJECTED` | new evaluation is rejected by policy |
| `GITHUB_REF_NOT_PINNED` | GitHub ref is floating |
| `LOCKFILE_INVALID` | installed lockfile is invalid |
| `GITHUB_SOURCE_INVALID` | invalid GitHub source in lock |
| `SOURCE_METADATA_INVALID` | source metadata validation failed |
| `SOURCE_PREPARE_FAILED` | source preparation/materialization failed |
| `EVALUATION_ERROR` | scan/evaluation failed |

Fatal command-level errors (`status=ERROR`) use:

| error_code | Meaning |
| --- | --- |
| `UPDATE_ARGS_INVALID` | CLI argument parse/validation failed |
| `UPDATE_TARGET_INVALID` | update target spec is invalid |
| `UPDATE_TARGET_READ_FAILED` | resolved target path cannot be read |
| `UPDATE_POLICY_LOAD_FAILED` | policy file load/parse/validation failed |
| `UPDATE_REPORT_BUILD_FAILED` | update report build failed for other reasons |
| `UPDATE_FAILED` | fallback when update fatal error classification is unavailable |

When available, update JSON fatal errors also include optional `rule_id`
derived from rule-prefixed target/report validation messages.
Update skill items also include `severity_overrides`, inherited from installed
lock policy metadata for audit visibility.
Update skill items also include `severity_override_diff` (`added`/`removed`)
to show override applicability drift between installed snapshot and current
source evaluation.
Update skill items also include `risk_score` (`model`, `previous`, `current`,
`delta`, `signals`) for differential risk scoring that combines severity-weighted
finding changes with new URL/executable/file-delta/override-delta signals.

## Exit Code Contract

CLI exit codes are stable for automation:

| Command | `0` | `1` | `2` |
| --- | --- | --- | --- |
| `gokui fetch` | fetched successfully | fatal error | n/a |
| `gokui inspect` | pass or inspect-only pre-release result | fatal error | policy rejected (`decision=REJECTED`) |
| `gokui install` | installed / already installed (matching provenance) | fatal error | policy rejected (`decision=REJECTED`) |
| `gokui update --dry-run` | no rejected or error skill items | at least one `ERROR` item | at least one `REJECTED` item and no `ERROR` items |
| `gokui lock verify` | verified | fatal error | drift detected |

Status and error-code combinations are constrained as:

| `skills[].status` | Allowed `skills[].error_code` |
| --- | --- |
| `UP_TO_DATE` | `UP_TO_DATE` |
| `CHANGED` | `SOURCE_CHANGED` |
| `REJECTED` | `POLICY_REJECTED`, `GITHUB_REF_NOT_PINNED` |
| `ERROR` | `LOCKFILE_INVALID`, `GITHUB_SOURCE_INVALID`, `SOURCE_METADATA_INVALID`, `SOURCE_PREPARE_FAILED`, `EVALUATION_ERROR` |

## Rule Reference and Remediation Notes

The following high-signal `rule_id` values are intended for reviewer triage and
CI policy routing. Severity may vary by context/profile, but the remediation
guidance is stable.

| `rule_id` | Typical severity | Example trigger | Remediation notes |
| --- | --- | --- | --- |
| `DESCRIPTION_TOOL_INJECTION` | high | `description` contains execution/setup language (for example "run this script first") | Keep `description` as pure applicability text; move operational steps out of frontmatter. |
| `PROMPT_OVERRIDE_LANGUAGE` | high | instruction text asks to ignore/override prior prompts or system policy | Remove override language; require user-visible approval flow instead of hidden prompt control. |
| `UNPINNED_RUNTIME_TOOL` | high | `npx foo`, `uvx foo`, `go run ...@latest`, `source/. <(curl ...)` | Pin immutable versions/commits and require integrity/provenance review before install. |
| `LINK_SPOOFING_URL_MISMATCH` | high | markdown link display host differs from actual link target host | Make visible link text match destination host exactly; remove deceptive redirect chains. |
| `RAW_HTML_MARKUP` | medium | raw HTML blocks/inline tags embedded in markdown instructions | Replace with plain markdown text unless HTML is strictly required and manually reviewed. |
| `CONFUSABLE_FILENAME` | high | filename mixes ASCII with Cyrillic/Greek homoglyph characters (for example `payрal.md`) | Rename files to plain ASCII (or a single clear script) and avoid lookalike characters. |
| `NFKC_CHANGES_TEXT` | medium | Unicode compatibility normalization changes instruction semantics | Rewrite with plain ASCII or unambiguous Unicode; remove compatibility confusables. |
| `ARCHIVE_PATH_ESCAPE` | critical | archive entry resolves outside extraction root (`..`, absolute, canonical escape) | Rebuild archive with normalized relative paths and verify extraction root confinement. |
| `SYMLINK_IN_ARCHIVE` | critical | archive contains symlink entries | Remove symlinks from distributed bundle; ship regular files only. |
| `SYMLINK_IN_SCAN_SOURCE` | critical | scan source tree contains symlinked file/dir entry | Replace symlinked content with real files in the quarantined source before scanning. |
| `LOCK_VERIFY_PATH_SYMLINK_DETECTED` | fatal verify guard | `lock verify` target path includes a symlink component | Verify/install from canonical non-symlink paths only; fix target path resolution in automation. |

Operational guidance:

- Treat `critical` and `high` findings as release blockers in strict profile.
- For medium findings, require explicit reviewer acknowledgement in CI logs.
- Prefer removing risky patterns over allow-listing; keep overrides auditable and minimal.

## Supported Targets

The MVP target set is intentionally small:

```sh
gokui install ./skill --target codex
gokui install ./skill --target custom:/path/to/skills
```

Future targets may include other local agents, but target support should not
weaken the quarantine model. A target adapter only controls where a policy-passed
artifact is installed.

## What gokui Inspects

### Skill Structure

gokui validates that:

- `SKILL.md` exists at the skill root.
- YAML frontmatter starts the file.
- `name` uses a strict ASCII lowercase/digit/hyphen format.
- The skill directory name matches `name`.
- `description` is a pure activation condition, not an instruction block.
- duplicate YAML keys, anchors, aliases, merge keys, and custom tags are
  rejected.

Descriptions are treated as startup-sensitive text because local agents may use
them for implicit activation. A description that says "use this for every task",
"run setup.sh first", "ignore previous instructions", or "do not tell the user"
is not a normal applicability description.
Tool-execution or prompt-override description rejects include the rule marker
`DESCRIPTION_TOOL_INJECTION` in validation errors.

### Unicode and Text

gokui treats invisible or display-confusing characters as first-class threats.
In strict mode, instruction text rejects:

- Unicode Tags: `U+E0000..U+E007F`
- bidi controls: `U+202A..U+202E`, `U+2066..U+2069`
- zero-width characters: `U+200B..U+200F`, `U+2060`, `U+FEFF`
- variation selectors in text
- ANSI/OSC escape sequences
- C0/C1 controls except tab and normal line endings
- compatibility-normalization drift (`NFKC_CHANGES_TEXT`) with normalized
  rescanning

Review output must be neutralized. Dangerous runes are rendered as escaped code
points such as `\u{E0049}` instead of being passed raw to another agent.

### Markdown Instructions

`SKILL.md`, `references/**/*.md`, and README-like files are scanned for:

- prompt override language
- bounded fuzzy/typoglycemia matching for common prompt-override phrases
- stealth instructions
- tool execution requests
- secret access
- exfiltration
- external install/setup instructions
- Markdown or HTML link spoofing
- remote images and raw HTML

This is deliberately conservative. A skill that asks a user to paste a command
into a terminal, download a binary, disable quarantine, or extract a
password-protected archive is treated as suspicious even if it contains no
malware file itself.

### Scripts and Commands

gokui does not execute bundled scripts during inspection.

It statically scans shell, Python, JavaScript, TypeScript, PowerShell, batch,
Ruby, Go, shebang files, executable files, and common dependency manifests.

Critical patterns include:

- `curl | sh`, `wget | bash`, or equivalent network-to-interpreter flows
- `base64 -d | sh`, `xxd -r -p | sh`, `eval`, `EncodedCommand`, and similar obfuscation
- `chmod +x` followed by local execution of the same artifact
- access to `.env`, `~/.ssh`, `~/.aws`, browser profiles, keychains, wallets,
  cookies, or API tokens combined with network send
- persistence through shell startup files, cron, launch agents, services, or
  user config directories
- unpinned runtime tools such as `npx foo`, `uvx foo`, `bunx foo`,
  `pnpm dlx foo`, `yarn dlx foo`, `npm exec foo`, `go run github.com/org/tool`
  (with no version) or `go run ...@latest` / `go run ...@main`, plus floating
  dist-tags/ranges like `npx foo@next` or `npx foo@^1.2.3`, or
  remote script imports (including `source <(curl ...)`, `. <(curl ...)`, and
  `corepack pnpm/yarn/npm ...` wrappers)

### Archives

Archives are never extracted directly into an agent skill directory.

Every entry is checked before materialization:

- absolute paths are rejected
- `..` path traversal is rejected
- final canonical paths must stay under the quarantine root
- symlinks, hardlinks, devices, and FIFOs are rejected
- file count and byte limits are enforced
- extraction targets must be empty

Archive path/symlink rejects include rule markers such as
`ARCHIVE_PATH_ESCAPE` and `SYMLINK_IN_ARCHIVE` in error messages.

## Policy Profiles

The default profile is `strict`.

Example policy shape:

```toml
[profile.strict]
allow_scripts = false
allow_network_in_instructions = false
allow_external_binaries = false
allow_unpinned_tools = false
allow_unicode_invisibles = false
max_files = 100
max_total_bytes = 5_000_000
max_text_file_bytes = 500_000
on_high = "reject"
on_medium = "warn"

[profile.team]
allow_scripts = true
script_executable_default = false
allow_network_in_instructions = false
allow_external_binaries = false
allow_unpinned_tools = false
trusted_domains = ["github.com", "raw.githubusercontent.com", "docs.python.org"]
on_high = "reject"
on_medium = "warn"

[profile.research]
allow_scripts = true
allow_network_in_instructions = true
allow_external_binaries = false
on_critical = "reject"
on_high = "warn"
```

Profiles change policy decisions; they do not skip provenance recording or safe
materialization.

## Example Report

```text
Source
  repo: github.com/evil/example
  ref: main
  resolved: 91af3c...
  warning: floating ref was resolved to commit; install requires pinning

Skill
  name: google
  description: Use when you need to interact with Google services...

Decision
  REJECTED

Findings
  CRITICAL FAKE_PREREQ_EXECUTION
    SKILL.md:18
    "requires openclaw-core ... download ... run"
    reason: prerequisite text instructs user to download and run external binary

  HIGH EXTERNAL_BINARY_DOWNLOAD
    SKILL.md:18
    url: github.com/.../openclawcore-1.0.3.zip
    reason: external executable archive in setup instructions

Next action
  not installed
```

Unicode findings are rendered without emitting the raw hidden text:

```text
CRITICAL UNICODE_TAG_IN_INSTRUCTIONS
  file: SKILL.md
  line: 5
  count: 64
  preview escaped:
    \u{E0049}\u{E004D}\u{E0050}\u{E004F}
  decoded ascii preview:
    "IMPORTANT: ..."
  action: rejected
```

## Lockfile and Provenance

Install records provenance in `gokui.lock` and keeps a machine-readable report
beside the installed skill.

```json
{
  "schema": "gokui.lock/v1",
  "name": "pdf-helper",
  "installed_at": "2026-05-21T00:00:00Z",
  "source": {
    "type": "github",
    "input": "github:org/repo//skills/pdf-helper@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
    "kind": "github-source"
  },
  "skill": {
    "root_sha256": "...",
    "files": [
      {
        "path": "SKILL.md",
        "sha256": "...",
        "bytes": 4210
      }
    ]
  },
  "policy": {
    "profile": "strict",
    "decision": "pass",
    "severity_overrides": []
  },
  "findings": {
    "critical": 0,
    "high": 0,
    "medium": 2,
    "low": 3
  }
}
```

If an installed skill named `pdf-helper` came from one source, installing a new
`pdf-helper` from another source is rejected unless the user performs an
explicit, provenance-aware replacement.

## Non-Goals

gokui does not:

- execute untrusted setup scripts to see what they do
- ask an LLM to review raw `SKILL.md`
- guarantee that policy-passed skills are safe
- replace runtime sandboxing or tool permission controls
- silently update installed skills from floating references

If AI-assisted review is added later, gokui must first neutralize invisible
characters, URLs, code blocks, and instruction-like content into structured data
so the reviewer itself is not exposed to raw prompt injection.

## License

Apache-2.0. See [LICENSE](LICENSE).
