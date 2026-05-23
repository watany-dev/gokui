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
		"gokui inspect <local-dir|zip|github-source>",
		"gokui install <source> --target codex --profile strict",
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
		"gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir> [--format human|json]",
		"gokui inspect <local-dir|zip|github-source> [--format human|json|sarif]",
		"gokui install <source> --target codex --profile strict [--format human|json]",
		"gokui update --dry-run [--target codex|custom:/path] [--format human|json]",
		"gokui lock verify [path] [--format human|json]",
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

func TestLockfileExampleSchemaSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	start := strings.Index(readme, "## Lockfile and Provenance")
	if start < 0 {
		t.Fatal("README missing Lockfile and Provenance section")
	}
	end := strings.Index(readme[start:], "## Non-Goals")
	if end < 0 {
		t.Fatal("README missing Non-Goals section after Lockfile and Provenance")
	}
	section := readme[start : start+end]

	required := []string{
		`"schema": "gokui.lock/v1"`,
		`"source": {`,
		`"type": "github"`,
		`"input": "github:org/repo//skills/pdf-helper@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"`,
		`"kind": "github-source"`,
	}
	for _, line := range required {
		if !strings.Contains(section, line) {
			t.Fatalf("README lockfile example missing line: %q", line)
		}
	}

	legacyKeys := []string{
		`"repo":`,
		`"path": "skills/pdf-helper"`,
		`"commit":`,
		`"archive_sha256":`,
	}
	for _, key := range legacyKeys {
		if strings.Contains(section, key) {
			t.Fatalf("README lockfile example still contains legacy key: %q", key)
		}
	}
}

func TestREADMEStatusStatementIsConsistentWithImplementedPreRelease(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)

	if strings.Contains(readme, "does not yet contain a\nworking release") {
		t.Fatal("README contains stale status statement about lacking a working release")
	}
	if !strings.Contains(readme, "pre-release software under active hardening") {
		t.Fatal("README should explicitly state pre-release hardening status")
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
		"| `gokui inspect` | pass or inspect-only pre-release result | fatal error | policy rejected (`decision=REJECTED`) |",
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
}

func TestReleaseChecklistDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	if !strings.Contains(readme, "Release execution checklist: [RELEASE.md](RELEASE.md)") {
		t.Fatal("README should link to RELEASE.md checklist")
	}

	releaseBytes, err := os.ReadFile("../../RELEASE.md")
	if err != nil {
		t.Fatalf("failed to read RELEASE.md: %v", err)
	}
	releaseDoc := string(releaseBytes)
	required := []string{
		"make release-check",
		"make release-check-offline",
		"make inspect-sarif",
		"make release-evidence",
		"make vuln",
		"VULN_GOTOOLCHAIN=go1.26.3+auto",
	}
	for _, line := range required {
		if !strings.Contains(releaseDoc, line) {
			t.Fatalf("RELEASE.md missing checklist command: %q", line)
		}
	}
	if !strings.Contains(releaseDoc, "[RELEASE_EVIDENCE_TEMPLATE.md](RELEASE_EVIDENCE_TEMPLATE.md)") {
		t.Fatal("RELEASE.md should link RELEASE_EVIDENCE_TEMPLATE.md")
	}

	templateBytes, err := os.ReadFile("../../RELEASE_EVIDENCE_TEMPLATE.md")
	if err != nil {
		t.Fatalf("failed to read RELEASE_EVIDENCE_TEMPLATE.md: %v", err)
	}
	template := string(templateBytes)
	templateRequired := []string{
		"Candidate commit SHA:",
		"`make release-check`:",
		"`make vuln` (required before final publication):",
		"Ready for release: `yes/no`",
	}
	for _, line := range templateRequired {
		if !strings.Contains(template, line) {
			t.Fatalf("RELEASE_EVIDENCE_TEMPLATE.md missing line: %q", line)
		}
	}
	if !strings.Contains(releaseDoc, "releases/evidence/<timestamp>-<commit>.md") {
		t.Fatal("RELEASE.md should describe release evidence output path")
	}
}

func TestReleaseCheckDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)

	required := []string{
		"make release-check",
		"make release-check RELEASE_CHECK_VULN=0",
		"make release-check-offline",
		"make inspect-sarif",
		"inspect-sarif smoke generation, and govulncheck",
	}
	for _, line := range required {
		if !strings.Contains(readme, line) {
			t.Fatalf("README missing release-check documentation line: %q", line)
		}
	}
}

func TestCISetupGoUsesLatestPatch(t *testing.T) {
	ciBytes, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("failed to read ci workflow: %v", err)
	}
	ci := string(ciBytes)
	if !strings.Contains(ci, "check-latest: true") {
		t.Fatal("ci workflow should set check-latest: true for setup-go")
	}

	setupGoCount := strings.Count(ci, "uses: actions/setup-go@")
	checkLatestCount := strings.Count(ci, "check-latest: true")
	if checkLatestCount < setupGoCount {
		t.Fatalf("ci workflow should set check-latest for every setup-go step: setup-go=%d check-latest=%d", setupGoCount, checkLatestCount)
	}
}

func TestMakefileVulnToolchainBaselineSync(t *testing.T) {
	makefileBytes, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatalf("failed to read Makefile: %v", err)
	}
	makefile := string(makefileBytes)

	required := []string{
		"VULN_GOTOOLCHAIN ?= go1.26.3+auto",
		"GOTOOLCHAIN=$(VULN_GOTOOLCHAIN) $(GO) tool govulncheck ./...",
	}
	for _, line := range required {
		if !strings.Contains(makefile, line) {
			t.Fatalf("Makefile missing vuln toolchain baseline line: %q", line)
		}
	}
}
