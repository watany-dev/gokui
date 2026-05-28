package app

import (
	"os"
	"strings"
	"testing"
)

func TestCommandSetDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	agentsBytes, err := os.ReadFile("../../AGENTS.md")
	if err != nil {
		t.Fatalf("failed to read AGENTS.md: %v", err)
	}

	readme := string(readmeBytes)
	agents := string(agentsBytes)

	required := []string{
		"gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir>",
		"gokui inspect <local-dir|zip|tar|github-source>",
		"gokui vet <local-dir|zip|tar>",
		"gokui install <source> --target codex --profile strict|team|research",
		"gokui update --dry-run",
		"gokui lock verify",
	}

	for _, line := range required {
		if !strings.Contains(readme, line) {
			t.Fatalf("README.md missing documented command line: %q", line)
		}
		if !strings.Contains(agents, line) {
			t.Fatalf("AGENTS.md missing documented command line: %q", line)
		}
	}
}

func TestCLIUsageSyntaxDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	usageText := usage()

	required := []string{
		"gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir> [--format human|json|sarif|compact]",
		"gokui inspect <local-dir|zip|tar|github-source> [--format human|json|sarif|compact|review-json]",
		"gokui vet <local-dir|zip|tar> [--profile strict|team|research] [--format human|json|sarif|compact|review-json]",
		"gokui install <source> --target codex --profile strict|team|research [--format human|json|sarif|compact] [--override RULE_ID ...]",
		"gokui update --dry-run [--target codex|custom:/path] [--format human|json|sarif|compact]",
		"gokui lock verify [path] [--format human|json|sarif|compact]",
	}

	for _, line := range required {
		if !strings.Contains(readme, line) {
			t.Fatalf("README.md missing detailed CLI syntax: %q", line)
		}
		if !strings.Contains(usageText, line) {
			t.Fatalf("usage() missing detailed CLI syntax: %q", line)
		}
	}
}

func TestStructuredErrorStreamContractDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)
	releaseBytes, err := os.ReadFile("../../RELEASE.md")
	if err != nil {
		t.Fatalf("failed to read RELEASE.md: %v", err)
	}
	releaseDoc := string(releaseBytes)

	required := []string{
		"For fatal errors, `human` and `compact` write diagnostics to `stderr`.",
		"`json`, `sarif`, and `review-json` write structured error reports to `stdout`",
	}
	for _, line := range required {
		if !strings.Contains(readme, line) {
			t.Fatalf("README missing structured error stream contract line: %q", line)
		}
	}

	requiredRoadmap := "deterministic error stream contract: `human`/`compact` errors to `stderr`, `json`/`sarif`/`review-json` structured errors to `stdout`"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing structured error stream contract line: %q", requiredRoadmap)
	}

	requiredRelease := []string{
		"fatal `human`/`compact` diagnostics to `stderr`",
		"fatal `json`/`sarif`/`review-json` structured reports to `stdout`",
	}
	for _, line := range requiredRelease {
		if !strings.Contains(releaseDoc, line) {
			t.Fatalf("RELEASE missing structured error stream contract line: %q", line)
		}
	}
}

func TestExitCodeContractDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)

	rows := []string{
		"| `gokui fetch` | fetched successfully | fatal error | n/a |",
		"| `gokui inspect` | pass | fatal error | policy rejected (`decision=REJECTED`) |",
		"| `gokui install` | installed / already installed (matching provenance) | fatal error | policy rejected (`decision=REJECTED`) |",
		"| `gokui update --dry-run` | no rejected or error skill items | at least one `ERROR` item | at least one `REJECTED` item and no `ERROR` items |",
		"| `gokui lock verify` | verified | fatal error | drift detected |",
	}
	for _, row := range rows {
		if !strings.Contains(readme, row) {
			t.Fatalf("README missing exit code contract row: %q", row)
		}
	}
}

func TestUpdateStatusErrorCodeMatrixDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)

	rows := []string{
		"| `UP_TO_DATE` | `UP_TO_DATE` |",
		"| `CHANGED` | `SOURCE_CHANGED` |",
		"| `REJECTED` | `POLICY_REJECTED`, `GITHUB_REF_NOT_PINNED` |",
		"| `ERROR` | `LOCKFILE_INVALID`, `GITHUB_SOURCE_INVALID`, `SOURCE_METADATA_INVALID`, `SOURCE_PREPARE_FAILED`, `EVALUATION_ERROR` |",
	}
	for _, row := range rows {
		if !strings.Contains(readme, row) {
			t.Fatalf("README missing update status/error_code matrix row: %q", row)
		}
	}

	requiredAuditLines := []string{
		"Install JSON reports and generated lockfiles also include",
		"`severity_overrides` as an audit trail field",
		"Update skill items also include `severity_overrides`",
		"Update skill items also include `severity_override_diff`",
		"Update skill items also include `risk_score`",
	}
	for _, line := range requiredAuditLines {
		if !strings.Contains(readme, line) {
			t.Fatalf("README missing severity override audit documentation line: %q", line)
		}
	}

	releaseCheckErrorCodeLines := []string{
		"### release-check (`make release-check`, stderr codes)",
		"| `RC_PREFLIGHT_BUILD_OUT_INVALID` |",
		"| `RC_PREFLIGHT_SARIF_OUT_INVALID` |",
		"| `RC_PREFLIGHT_BUILD_OUT_SYMLINK` |",
		"| `RC_PREFLIGHT_SARIF_OUT_SYMLINK` |",
		"| `RC_PREFLIGHT_OUTPUT_PATH_CONFLICT` |",
		"| `RC_PREFLIGHT_BUILD_OUT_EXISTS` |",
		"| `RC_PREFLIGHT_SARIF_OUT_EXISTS` |",
		"| `RC_CLEANUP_REMOVE_FAILED` |",
		"| `RC_CLEANUP_REMOVE_FAILED_SUMMARY` |",
	}
	for _, line := range releaseCheckErrorCodeLines {
		if !strings.Contains(readme, line) {
			t.Fatalf("README missing release-check error code reference line: %q", line)
		}
	}
}
