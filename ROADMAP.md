# Roadmap

This roadmap follows gokui's core position: it is a quarantine gate for Agent
Skill bundles, not a convenience-first package manager.

## Current Implementation Snapshot (May 23, 2026)

The following items are implemented in the current codebase and validated by
tests/CI:

- CLI commands: `fetch`, `inspect`, `install`, `update --dry-run`, `lock verify`
- Quarantine-safe archive materialization for inspect/install flows
- Strict skill frontmatter validation and markdown/script scanning
- Commit-pinned GitHub source fetch and install/update/verify provenance checks
- Atomic install with `.gokui-report.json` and `gokui.lock`
- Lock drift verification with per-check machine-readable codes
- Stable JSON output contracts for all MVP commands
- Machine-readable `error_code` support across command failure paths
- SARIF output for `inspect` (`--format sarif`) for CI/code scanning integration
- CI SARIF smoke job for inspect output generation and artifact capture
- CI setup-go hardening to resolve the latest available Go patch release
- `make vuln` hardened with patched Go toolchain baseline (`go1.26.3+auto`)
- automated offline release evidence collection with per-step logs
- automated online release evidence collection mode (includes vuln step)
- URL risk classification for shortener hosts and raw-IP URLs
- URL risk classification for paste-site URLs and GitHub release asset URLs
- URL risk classification for remote image URLs in markdown content
- raw HTML markup detection in markdown scanning
- markdown link-spoofing detection (display host vs target host mismatch)
- critical detection of Unicode Tags and bidi controls in scanned text

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
- Flag unpinned runtime tools:
  - `npx foo`
  - `uvx foo`
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
- Add compact summary output for CI logs.
- Add `gokui vet` for skill authors.
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
- Add structured neutralized-review export for optional human or AI-assisted
  review.
- Add trusted publisher or signature support.
- Add organization policy bundles.
- Add repository-level `.gokui-policy.toml` for CI use.
- Add differential risk scoring for updates.
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
| `ARCHIVE_PATH_ESCAPE` | archive entry resolves outside quarantine |
| `SYMLINK_IN_ARCHIVE` | archive contains symlink or hardlink |
| `SECRET_EXFIL` | secret read combined with network send |
| `FAKE_PREREQ_EXECUTION` | prerequisite language plus download/run instruction |
| `DESCRIPTION_TOOL_INJECTION` | description includes tool execution or override instruction |

High findings reject under `strict`:

| Rule | Condition |
| --- | --- |
| `UNPINNED_RUNTIME_TOOL` | `npx`, `uvx`, `go run`, or similar floating execution |
| `EXTERNAL_BINARY_DOWNLOAD` | release asset or binary download instruction |
| `PASSWORD_PROTECTED_ARCHIVE` | password-protected archive instruction |
| `RAW_IP_URL` | URL host is an IP address |
| `SHORTENER_URL` | shortener or paste-site URL |
| `ALLOWED_TOOLS_BASH_WILDCARD` | broad `Bash` or wildcard tool permission |
| `WRITES_HOME_CONFIG` | writes to shell rc, ssh, cron, launch agents, or similar |

Medium findings warn under `strict`:

| Rule | Condition |
| --- | --- |
| `REMOTE_IMAGE_OR_HTML` | remote Markdown image or raw HTML |
| `LARGE_TEXT_OR_BINARY` | unusually large file for a skill |
| `UNKNOWN_FILE_TYPE` | binary or unclassified file |
| `NFKC_CHANGES_TEXT` | Unicode normalization changes text |
| `MIXED_SCRIPT_FILENAME` | filename uses mixed scripts or confusable text |

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
