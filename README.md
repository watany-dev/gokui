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

gokui is currently in early design. The repository does not yet contain a
working release. `inspect` now performs pre-release structural validation and
basic markdown threat scanning, and emits a draft JSON/human report with
`PASS`/`REJECTED` decisions. In JSON mode, fatal inspect failures emit
machine-readable top-level `error_code` for automation. For GitHub sources, floating refs remain
inspect-only pre-release stubs, while commit-pinned refs are fetched and
scanned.
`install` now supports local-dir/zip/tar sources with `--profile strict`,
rejects high/critical findings, installs atomically to `--target codex` or
`--target custom:/path`, writes `.gokui-report.json` and `gokui.lock`, allows
idempotent reinstall only when provenance matches, and rejects same-name
different-provenance installs. It also supports commit-pinned GitHub sources
(`github:owner/repo//path@<sha>`) via safe tarball materialization. In JSON
mode, rejected installs set report `error_code=INSTALL_POLICY_REJECTED`, and
fatal errors emit a machine-readable error envelope with top-level `error_code`.
`lock verify` now validates installed files against `gokui.lock`, checks source
field consistency (including strict GitHub source syntax and commit pinning),
validates lock/report structural integrity, validates GitHub source metadata
integrity, reports drift, and emits per-check `code` fields in JSON output for
automation. On fatal verify errors, JSON output includes top-level `error_code`.
(missing/changed/unexpected files).
`update --dry-run` now re-evaluates installed skills from lockfile source
provenance for local-dir/zip/tar sources, reports added/removed/changed files,
risk deltas, and new URL/executable signals. For GitHub sources, commit-pinned
refs are evaluated and floating refs are rejected. JSON output now emits stable
skill-item keys for automation-friendly parsing, including `error_code` for
status-aware automation.
JSON output contracts are now stability-tested across `inspect`, `fetch`,
`install`, `update`, `lock verify`, and install metadata files.
`fetch` now supports commit-pinned GitHub sources and materializes them into a
quarantine output root via `--out`, and records `.gokui-source.json`
provenance metadata. In JSON mode, fetch failures return `error_code` for
automation.
GitHub source syntax is now strictly validated as
`github:owner/repo//path/to/skill@ref`; `install` requires commit-pinned refs
for GitHub sources and rejects floating refs. `install` and `update` validate
fetched source metadata for GitHub-origin skills.
Local directory inspect already enforces that `SKILL.md` exists at the skill
root.
It also validates strict YAML frontmatter rules (no duplicate keys, anchors,
aliases, merge keys, or custom tags), requires a valid `name` that matches the
directory name, and enforces safety-oriented `description` checks.
For local zip/tar inputs, inspect now performs safe archive materialization
checks (path escape, symlink/hardlink/special entry rejection, and size/count
limits) before applying skill validation.

The intended first release focuses on local inspection and strict Codex-targeted
installation:

```sh
gokui inspect <local-dir|zip|github-source>
gokui install <source> --target codex --profile strict
gokui update --dry-run
gokui lock verify
```

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
gokui install .gokui/quarantine/pdf-helper --target codex --profile strict
gokui update --target codex --dry-run
```

The intended flow is:

1. Fetch into a quarantine directory.
2. Materialize archives safely without writing outside quarantine.
3. Validate the skill structure and frontmatter.
4. Scan text, Markdown, scripts, dependencies, URLs, and decoded payloads.
5. Make a policy decision.
6. Install atomically with normalized permissions, a lockfile, and a report.

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

### Unicode and Text

gokui treats invisible or display-confusing characters as first-class threats.
In strict mode, instruction text rejects:

- Unicode Tags: `U+E0000..U+E007F`
- bidi controls: `U+202A..U+202E`, `U+2066..U+2069`
- zero-width characters: `U+200B..U+200F`, `U+2060`, `U+FEFF`
- variation selectors in text
- ANSI/OSC escape sequences
- C0/C1 controls except tab and normal line endings

Review output must be neutralized. Dangerous runes are rendered as escaped code
points such as `\u{E0049}` instead of being passed raw to another agent.

### Markdown Instructions

`SKILL.md`, `references/**/*.md`, and README-like files are scanned for:

- prompt override language
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
- `base64 -d | sh`, `eval`, `EncodedCommand`, and similar obfuscation
- access to `.env`, `~/.ssh`, `~/.aws`, browser profiles, keychains, wallets,
  cookies, or API tokens combined with network send
- persistence through shell startup files, cron, launch agents, services, or
  user config directories
- unpinned runtime tools such as `npx foo`, `uvx foo`, `go run ...@latest`, or
  remote script imports

### Archives

Archives are never extracted directly into an agent skill directory.

Every entry is checked before materialization:

- absolute paths are rejected
- `..` path traversal is rejected
- final canonical paths must stay under the quarantine root
- symlinks, hardlinks, devices, and FIFOs are rejected
- file count and byte limits are enforced
- extraction targets must be empty

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
    "repo": "org/repo",
    "path": "skills/pdf-helper",
    "commit": "8f3c2d1a4b5c6d7e8f901234567890abcdef1234...",
    "archive_sha256": "..."
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
    "decision": "pass-with-warnings"
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
