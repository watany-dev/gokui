package app

import (
	"fmt"
	"io"
	"strings"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
)

type Config struct {
	Version string
	Commit  string
	Date    string
}

const (
	reportStatusError       = "ERROR"
	reportDecisionRejected  = "REJECTED"
	reportDecisionFetchDone = "FETCHED"
)

const (
	inspectErrorCodeArgsInvalid         = "INSPECT_ARGS_INVALID"
	inspectErrorCodeSourceNotFound      = "INSPECT_SOURCE_NOT_FOUND"
	inspectErrorCodeSourceInvalid       = "INSPECT_SOURCE_INVALID"
	inspectErrorCodeGitHubRefNotPinned  = "INSPECT_GITHUB_REF_NOT_PINNED"
	inspectErrorCodeSourcePrepareFailed = "INSPECT_SOURCE_PREPARE_FAILED"
	inspectErrorCodeScanFailed          = "INSPECT_SCAN_FAILED"
	inspectErrorCodePolicyLoadFailed    = "INSPECT_POLICY_LOAD_FAILED"
	inspectErrorCodeUnknown             = "INSPECT_FAILED"
)

func BuildVersionString(cfg Config) string {
	version := cfg.Version
	if version == "" {
		version = "dev"
	}

	commit := cfg.Commit
	if commit == "" {
		commit = "none"
	}

	date := cfg.Date
	if date == "" {
		date = "unknown"
	}

	return fmt.Sprintf("%s (%s, %s)", version, commit, date)
}

func Run(args []string, stdout io.Writer, stderr io.Writer, cfg Config) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, usage())
		return exitcode.Error.Int()
	}

	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		return runHelp(args[1:], stdout, stderr)
	}

	if args[0] == "version" {
		if hasHelpFlag(args[1:]) {
			return runHelp([]string{"version"}, stdout, stderr)
		}
		if len(args) == 1 {
			_, _ = fmt.Fprintln(stdout, BuildVersionString(cfg))
			return exitcode.OK.Int()
		}
	}

	switch args[0] {
	case "fetch":
		if hasHelpFlag(args[1:]) {
			return runHelp([]string{"fetch"}, stdout, stderr)
		}
		return runFetch(args[1:], stdout, stderr)
	case "inspect":
		if hasHelpFlag(args[1:]) {
			return runHelp([]string{"inspect"}, stdout, stderr)
		}
		return runInspect(args[1:], stdout, stderr)
	case "vet":
		if hasHelpFlag(args[1:]) {
			return runHelp([]string{"vet"}, stdout, stderr)
		}
		return runVet(args[1:], stdout, stderr)
	case "install":
		if hasHelpFlag(args[1:]) {
			return runHelp([]string{"install"}, stdout, stderr)
		}
		return runInstall(args[1:], stdout, stderr)
	case "update":
		if hasHelpFlag(args[1:]) {
			return runHelp([]string{"update"}, stdout, stderr)
		}
		return runUpdate(args[1:], stdout, stderr)
	case "lock":
		if len(args) >= 2 && args[1] == "verify" {
			if hasHelpFlag(args[2:]) {
				return runHelp([]string{"lock", "verify"}, stdout, stderr)
			}
			return runLockVerify(args[2:], stdout, stderr)
		}
		if hasHelpFlag(args[1:]) {
			return runHelp([]string{"lock", "verify"}, stdout, stderr)
		}
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s\n", strings.Join(args, " "), usage())
		return exitcode.Error.Int()
	}

	_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s\n", strings.Join(args, " "), usage())
	return exitcode.Error.Int()
}

func usage() string {
	return strings.TrimSpace(`
gokui is pre-release software.

usage:
  gokui version
  gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir> [--format human|json|sarif|compact]
  gokui inspect <local-dir|zip|tar|github-source> [--format human|json|sarif|compact|review-json]
  gokui vet <local-dir|zip|tar> [--profile strict|team|research] [--format human|json|sarif|compact|review-json]
  gokui install <source> --target codex --profile strict|team|research [--format human|json|sarif|compact] [--override RULE_ID ...]
  gokui update --dry-run [--target codex|custom:/path] [--format human|json|sarif|compact]
  gokui lock verify [path] [--format human|json|sarif|compact]`)
}
