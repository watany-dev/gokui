package app

import (
	"fmt"
	"io"
	"strings"
)

type commandHelp struct {
	name  string
	short string
	full  string
}

var commandHelps = []commandHelp{
	{"version", "Print version, commit, and build date.", versionHelpText},
	{"fetch", "Download a skill from a GitHub source into a quarantine directory.", fetchHelpText},
	{"inspect", "Validate structure and scan for security risks (no policy decision).", inspectHelpText},
	{"vet", "Inspect and apply a policy profile to produce a PASS/REJECTED decision.", vetHelpText},
	{"install", "Fetch, inspect, apply policy, and atomically install with lockfile.", installHelpText},
	{"update", "Re-evaluate installed skills against their lockfile (dry-run only).", updateHelpText},
	{"lock verify", "Verify an installed skill matches its lockfile.", lockVerifyHelpText},
}

func findCommandHelp(name string) (commandHelp, bool) {
	for _, h := range commandHelps {
		if h.name == name {
			return h, true
		}
	}
	return commandHelp{}, false
}

func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return true
		}
	}
	return false
}

func runHelp(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stdout, topLevelHelp())
		return 0
	}

	key := args[0]
	if len(args) >= 2 {
		joined := args[0] + " " + args[1]
		if _, ok := findCommandHelp(joined); ok {
			key = joined
		}
	}

	h, ok := findCommandHelp(key)
	if !ok {
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s\n", strings.Join(args, " "), topLevelHelp())
		return 1
	}

	_, _ = fmt.Fprintln(stdout, h.full)
	return 0
}

func topLevelHelp() string {
	var b strings.Builder
	b.WriteString("gokui - quarantine gate for Agent Skill bundles (pre-release).\n\n")
	b.WriteString("Usage:\n")
	b.WriteString("  gokui <command> [arguments]\n")
	b.WriteString("  gokui help [<command>]\n")
	b.WriteString("  gokui <command> --help\n\n")
	b.WriteString("Commands:\n")

	width := 0
	for _, h := range commandHelps {
		if len(h.name) > width {
			width = len(h.name)
		}
	}
	for _, h := range commandHelps {
		b.WriteString(fmt.Sprintf("  %-*s  %s\n", width, h.name, h.short))
	}
	b.WriteString("\nRun 'gokui help <command>' for detailed usage of a specific command.")
	return b.String()
}

const versionHelpText = `gokui version

Print the gokui version, commit hash, and build date.

Usage:
  gokui version

Example:
  gokui version

Exit codes:
  0  success`

const fetchHelpText = `gokui fetch

Download an Agent Skill bundle from a GitHub source into a quarantine directory.
Records provenance metadata (.gokui-source.json) for downstream commands.

Usage:
  gokui fetch <github-source> --out <quarantine-dir> [--format human|json|sarif|compact]

Arguments:
  <github-source>   github:owner/repo//path/to/skill@commit
                    (commit must be a 40-hex lowercase SHA; floating refs are rejected)

Flags:
  --out <dir>       Output directory for the quarantined skill (required)
  --format <fmt>    Output format: human (default), json, sarif, compact

Example:
  gokui fetch github:owner/repo//skills/foo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234 \
    --out .gokui/quarantine

Exit codes:
  0  fetched successfully
  1  fatal error (invalid args, unsupported source, download failure, etc.)`

const inspectHelpText = `gokui inspect

Validate skill structure and frontmatter, and scan for security risks in Markdown,
scripts, URLs, and decoded payloads. Reports findings without applying a policy decision.

Usage:
  gokui inspect <source> [--format human|json|sarif|compact|review-json]

Arguments:
  <source>          Local directory, .zip, .tar/.tar.gz, or github:owner/repo//path@commit
                    (GitHub sources require a commit-pinned ref)

Flags:
  --format <fmt>    Output format: human (default), json, sarif, compact, review-json

Examples:
  gokui inspect /path/to/skill --format json
  gokui inspect skill-bundle.zip --format review-json
  gokui inspect github:owner/repo//skills/foo@abc... --format sarif

Exit codes:
  0  PASS (no rejectable findings)
  1  fatal error (invalid args, source not found, scan failure, etc.)
  2  REJECTED (scan findings warrant rejection)`

const vetHelpText = `gokui vet

Run inspect internally and apply a policy profile to produce a PASS/REJECTED decision
based on configured severity thresholds. Local sources only - GitHub sources are not
accepted; fetch first if needed.

Usage:
  gokui vet <source> [--profile strict|team|research]
            [--format human|json|sarif|compact|review-json]

Arguments:
  <source>          Local directory, .zip, or .tar/.tar.gz

Flags:
  --profile <name>  Policy profile: strict (default), team, research
  --format <fmt>    Output format: human (default), json, sarif, compact, review-json

Example:
  gokui vet /path/to/skill --profile strict --format json

Exit codes:
  0  PASS (no findings above the reject threshold)
  1  fatal error (invalid args, GitHub source given, policy failure, etc.)
  2  REJECTED (findings exceed reject thresholds)`

const installHelpText = `gokui install

Fetch (if needed), inspect, apply policy, and atomically install a skill with a
lockfile and install report. Records provenance, digests, and policy metadata.

Usage:
  gokui install <source> --target codex|custom:/path
                         --profile strict|team|research
                         [--format human|json|sarif|compact]
                         [--override RULE_ID ...]

Arguments:
  <source>          Local directory, .zip, .tar, or github:owner/repo//path@commit
                    (GitHub sources require a commit-pinned ref)

Flags:
  --target <t>      Installation target: codex or custom:/absolute/path (required)
  --profile <name>  Policy profile: strict, team, research (required)
  --format <fmt>    Output format: human (default), json, sarif, compact
  --override <ID>   Explicitly downgrade a high-severity finding for the policy
                    decision; repeatable

Examples:
  gokui install /path/to/skill --target codex --profile strict
  gokui install github:owner/repo//skills/foo@abc... \
    --target custom:/opt/skills --profile team --override RULE_ID_1

Exit codes:
  0  installed (or already installed with matching provenance)
  1  fatal error
  2  REJECTED by policy`

const updateHelpText = `gokui update

Re-evaluate installed skills from lockfile provenance and report file/risk deltas
(new URLs, executables, overrides). Currently dry-run only - does not write changes.

Usage:
  gokui update --dry-run [--target codex|custom:/path]
               [--format human|json|sarif|compact]

Flags:
  --dry-run         Perform evaluation without installing (required)
  --target <t>      Target to evaluate against: codex (default) or custom:/absolute/path
  --format <fmt>    Output format: human (default), json, sarif, compact

Examples:
  gokui update --dry-run
  gokui update --dry-run --target custom:/opt/skills --format json

Exit codes:
  0  no items in REJECTED or ERROR state
  1  at least one item with ERROR status
  2  at least one item REJECTED (and none in ERROR)`

const lockVerifyHelpText = `gokui lock verify

Validate an installed skill against its lockfile (gokui.lock): source consistency,
structural integrity, file digest integrity, and file drift detection
(missing/changed/unexpected files).

Usage:
  gokui lock verify [path] [--format human|json|sarif|compact]

Arguments:
  [path]            Path to the skill root directory containing gokui.lock
                    (default: ".")

Flags:
  --format <fmt>    Output format: human (default), json, sarif, compact

Examples:
  gokui lock verify
  gokui lock verify ~/.codex/skills/my-skill --format json

Exit codes:
  0  verified (all checks OK)
  1  fatal error (invalid args, lockfile read/parse failure, etc.)
  2  drift detected (failed checks or missing/changed/unexpected files)`
