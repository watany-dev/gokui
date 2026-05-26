package app

import (
	"os"
	"regexp"
	"sort"
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

func TestAgentsReleaseCheckErrorCodeDocumentationSync(t *testing.T) {
	agentsBytes, err := os.ReadFile("../../AGENTS.md")
	if err != nil {
		t.Fatalf("failed to read AGENTS.md: %v", err)
	}
	agents := string(agentsBytes)

	required := []string{
		"Release-check machine-readable error codes are part of the current operational",
		"RC_PREFLIGHT_BUILD_OUT_INVALID",
		"RC_PREFLIGHT_SARIF_OUT_INVALID",
		"RC_PREFLIGHT_BUILD_OUT_SYMLINK",
		"RC_PREFLIGHT_SARIF_OUT_SYMLINK",
		"RC_PREFLIGHT_OUTPUT_PATH_CONFLICT",
		"RC_PREFLIGHT_BUILD_OUT_EXISTS",
		"RC_PREFLIGHT_SARIF_OUT_EXISTS",
		"RC_CLEANUP_REMOVE_FAILED",
		"RC_CLEANUP_REMOVE_FAILED_SUMMARY",
	}
	for _, line := range required {
		if !strings.Contains(agents, line) {
			t.Fatalf("AGENTS.md missing release-check error code documentation line: %q", line)
		}
	}
}

func TestAgentsReleaseCheckErrorCodeSetMatchesReadme(t *testing.T) {
	agentsBytes, err := os.ReadFile("../../AGENTS.md")
	if err != nil {
		t.Fatalf("failed to read AGENTS.md: %v", err)
	}
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}

	agentsCodes := extractReleaseCheckErrorCodesFromAgents(t, string(agentsBytes))
	readmeCodes := extractReleaseCheckErrorCodesFromReadmeAutomationSection(t, string(readmeBytes))

	agentsJoined := strings.Join(agentsCodes, ",")
	readmeJoined := strings.Join(readmeCodes, ",")
	if agentsJoined != readmeJoined {
		t.Fatalf("release-check code set mismatch between AGENTS.md and README.md\nAGENTS: %s\nREADME: %s", agentsJoined, readmeJoined)
	}
}

func TestReleaseCheckErrorCodeSetSyncAcrossPrimaryDocs(t *testing.T) {
	agentsBytes, err := os.ReadFile("../../AGENTS.md")
	if err != nil {
		t.Fatalf("failed to read AGENTS.md: %v", err)
	}
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	releaseBytes, err := os.ReadFile("../../RELEASE.md")
	if err != nil {
		t.Fatalf("failed to read RELEASE.md: %v", err)
	}

	agentsCodes := extractReleaseCheckErrorCodesFromAgents(t, string(agentsBytes))
	readmeCodes := extractReleaseCheckErrorCodesFromReadmeAutomationSection(t, string(readmeBytes))
	releaseCodes := extractReleaseCheckErrorCodesFromTable(t, string(releaseBytes), "RELEASE.md")

	agentsJoined := strings.Join(agentsCodes, ",")
	readmeJoined := strings.Join(readmeCodes, ",")
	releaseJoined := strings.Join(releaseCodes, ",")
	if agentsJoined != readmeJoined || readmeJoined != releaseJoined {
		t.Fatalf(
			"release-check code set mismatch across AGENTS.md / README.md / RELEASE.md\nAGENTS:  %s\nREADME:  %s\nRELEASE: %s",
			agentsJoined,
			readmeJoined,
			releaseJoined,
		)
	}
}

func TestReleaseCheckErrorCodeSetSyncAcrossSourceOfTruthDocs(t *testing.T) {
	agentsBytes, err := os.ReadFile("../../AGENTS.md")
	if err != nil {
		t.Fatalf("failed to read AGENTS.md: %v", err)
	}
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	releaseBytes, err := os.ReadFile("../../RELEASE.md")
	if err != nil {
		t.Fatalf("failed to read RELEASE.md: %v", err)
	}
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}

	agentsCodes := extractReleaseCheckErrorCodesFromAgents(t, string(agentsBytes))
	readmeCodes := extractReleaseCheckErrorCodesFromReadmeAutomationSection(t, string(readmeBytes))
	releaseCodes := extractReleaseCheckErrorCodesFromTable(t, string(releaseBytes), "RELEASE.md")
	roadmapCodes := extractReleaseCheckErrorCodesFromRoadmap(t, string(roadmapBytes))

	agentsJoined := strings.Join(agentsCodes, ",")
	readmeJoined := strings.Join(readmeCodes, ",")
	releaseJoined := strings.Join(releaseCodes, ",")
	roadmapJoined := strings.Join(roadmapCodes, ",")
	if agentsJoined != readmeJoined || readmeJoined != releaseJoined || releaseJoined != roadmapJoined {
		t.Fatalf(
			"release-check code set mismatch across AGENTS.md / README.md / RELEASE.md / ROADMAP.md\nAGENTS:  %s\nREADME:  %s\nRELEASE: %s\nROADMAP: %s",
			agentsJoined,
			readmeJoined,
			releaseJoined,
			roadmapJoined,
		)
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
		`"severity_overrides": []`,
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

func TestRuleRemediationDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)

	required := []string{
		"## Rule Reference and Remediation Notes",
		"| `rule_id` | Typical severity | Example trigger | Remediation notes |",
		"`DESCRIPTION_TOOL_INJECTION`",
		"`PROMPT_OVERRIDE_LANGUAGE`",
		"`UNPINNED_RUNTIME_TOOL`",
		"`LINK_SPOOFING_URL_MISMATCH`",
		"`RAW_HTML_MARKUP`",
		"`NFKC_CHANGES_TEXT`",
		"`ARCHIVE_PATH_ESCAPE`",
		"`ARCHIVE_SOURCE_CHANGED_DURING_OPEN`",
		"`ARCHIVE_SOURCE_SYMLINK_DETECTED`",
		"`ARCHIVE_SOURCE_SPECIAL_FILE`",
		"`SYMLINK_IN_ARCHIVE`",
		"`SYMLINK_IN_SCAN_SOURCE`",
		"`LOCK_VERIFY_PATH_SYMLINK_DETECTED`",
	}
	for _, line := range required {
		if !strings.Contains(readme, line) {
			t.Fatalf("README missing rule remediation documentation line: %q", line)
		}
	}
}

func TestReadmeCriticalPatternDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)

	required := []string{
		"curl | source /dev/stdin",
		"decode output piped to `source`/`.` via stdin",
		"quoted/escaped-quoted stdin targets",
		"embedded in quoted command strings",
		"optional or stacked `builtin`/`command` prefixes",
		"`command --` / `builtin --` forms",
		"`command -p` / `builtin -p` forms with optional `--`",
		"attached `command--` / `command-p` / `builtin--` / `builtin-p` forms",
		"equivalent stdin path spellings",
		"/dev//stdin",
		"repeated-slash `/dev//...` and `/proc//...` forms",
		"`fd/00...` forms",
		"/dev/fd/0",
		"/proc/thread-self/fd/0",
		"/proc/<pid>/fd/0",
		"/proc/self/task/<tid>/fd/0",
		"/proc/<pid>/task/<tid>/fd/0",
		"/proc/thread-self/task/<tid>/fd/0",
		"task-path `fd/00` variants",
	}
	for _, line := range required {
		if !strings.Contains(readme, line) {
			t.Fatalf("README missing critical pattern documentation line: %q", line)
		}
	}
}

func TestRoadmapCriticalPatternDocumentationSync(t *testing.T) {
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	required := []string{
		"critical detection of pipe-to-stdin source/dot execution chains",
		"quoted and escaped-quoted stdin targets",
		"optional or stacked `builtin`/`command` prefixes",
		"`command --` / `builtin --` forms",
		"`command -p` / `builtin -p` forms with optional `--`",
		"attached `command--` / `command-p` / `builtin--` / `builtin-p` forms",
		"equivalent stdin path spellings",
		"/dev//stdin",
		"repeated-slash `/dev//...` and `/proc//...` forms",
		"`fd/00...` forms",
		"task-path `fd/00` variants",
		"/dev/fd/0",
		"/proc/thread-self/fd/0",
		"/proc/<pid>/fd/0",
		"/proc/self/task/<tid>/fd/0",
		"/proc/<pid>/task/<tid>/fd/0",
		"/proc/thread-self/task/<tid>/fd/0",
	}
	for _, line := range required {
		if !strings.Contains(roadmap, line) {
			t.Fatalf("ROADMAP missing critical pattern documentation line: %q", line)
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
		"RELEASE_CHECK_BUILD_OUT=.cache/custom/gokui-release-check",
		"make release-check-offline",
		"make inspect-sarif",
		"make release-evidence",
		"make release-evidence-offline",
		"make release-evidence-online",
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
		"Mode (`offline` or `online`):",
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
		t.Fatal("RELEASE.md should describe release evidence template output path")
	}
	if !strings.Contains(releaseDoc, "releases/evidence/<timestamp>-<commit>-offline-audit.md") {
		t.Fatal("RELEASE.md should describe offline release evidence output path")
	}
	if !strings.Contains(releaseDoc, "releases/evidence/<timestamp>-<commit>-online-audit.md") {
		t.Fatal("RELEASE.md should describe online release evidence output path")
	}
	if !strings.Contains(releaseDoc, "git status --short") ||
		!strings.Contains(releaseDoc, "tracked and untracked") {
		t.Fatal("RELEASE.md should document tracked/untracked clean-tree check for evidence scripts")
	}
	if !strings.Contains(releaseDoc, ".cache/gokui-release-evidence") {
		t.Fatal("RELEASE.md should document isolated BUILD_OUT path for evidence scripts")
	}
	if !strings.Contains(releaseDoc, ".cache/gokui-release-check") {
		t.Fatal("RELEASE.md should document isolated release-check build output path")
	}
	if !strings.Contains(releaseDoc, "fails closed when build/SARIF output paths include symlink") || !strings.Contains(releaseDoc, "build and SARIF outputs") || !strings.Contains(releaseDoc, "resolve to the same path") {
		t.Fatal("RELEASE.md should document release-check build/SARIF output preflight fail-closed behavior")
	}
	if !strings.Contains(releaseDoc, "RC_PREFLIGHT_BUILD_OUT_INVALID") ||
		!strings.Contains(releaseDoc, "RC_PREFLIGHT_SARIF_OUT_INVALID") ||
		!strings.Contains(releaseDoc, "RC_PREFLIGHT_BUILD_OUT_SYMLINK") ||
		!strings.Contains(releaseDoc, "RC_PREFLIGHT_SARIF_OUT_SYMLINK") ||
		!strings.Contains(releaseDoc, "RC_PREFLIGHT_OUTPUT_PATH_CONFLICT") ||
		!strings.Contains(releaseDoc, "RC_PREFLIGHT_BUILD_OUT_EXISTS") ||
		!strings.Contains(releaseDoc, "RC_PREFLIGHT_SARIF_OUT_EXISTS") {
		t.Fatal("RELEASE.md should document release-check preflight machine-readable error codes")
	}
	if !strings.Contains(releaseDoc, "non-root file paths") ||
		!strings.Contains(releaseDoc, "under the repository root") ||
		!strings.Contains(releaseDoc, "directory-like paths ending with `/`") ||
		!strings.Contains(releaseDoc, "under `.git/`") ||
		!strings.Contains(releaseDoc, "must not contain `.` or `..` path") ||
		!strings.Contains(releaseDoc, "must not contain empty path segments") ||
		!strings.Contains(releaseDoc, "must end with `.sarif`") {
		t.Fatal("RELEASE.md should document release-check non-root/repository-root/non-directory/.git/dot-segment/extension output path guards")
	}
	if !strings.Contains(releaseDoc, "make inspect-sarif") ||
		!strings.Contains(releaseDoc, "output paths must resolve under the repository root") ||
		!strings.Contains(releaseDoc, "must resolve outside `.git/`") ||
		!strings.Contains(releaseDoc, "must not contain `..` path segments") ||
		!strings.Contains(releaseDoc, "must not contain `.` path segments") ||
		!strings.Contains(releaseDoc, "must not contain empty path segments") ||
		!strings.Contains(releaseDoc, "must be non-directory file paths") ||
		!strings.Contains(releaseDoc, "must end with `.sarif`") {
		t.Fatal("RELEASE.md should document inspect-sarif repository-root/.git/path-segment/non-directory/extension output path guards")
	}
	if !strings.Contains(releaseDoc, "preflight checks run before format/test/race/vuln gate") {
		t.Fatal("RELEASE.md should document release-check preflight-first execution ordering")
	}
	if !strings.Contains(releaseDoc, "release-check stderr error codes:") ||
		!strings.Contains(releaseDoc, "see `README.md` -> `Automation Error Codes` -> `release-check`") {
		t.Fatal("RELEASE.md should link release-check stderr code reference in README automation error section")
	}
	if !strings.Contains(releaseDoc, "mode (`offline` or `online`)") {
		t.Fatal("RELEASE.md should require recording evidence mode in captured metadata")
	}
	if !strings.Contains(releaseDoc, "fail closed when repository-root/output/log paths include") {
		t.Fatal("RELEASE.md should document fail-closed path hardening for release scripts")
	}
	if !strings.Contains(releaseDoc, "expected output/log files already exist") {
		t.Fatal("RELEASE.md should document output/log collision fail-closed behavior")
	}
	if !strings.Contains(releaseDoc, "created atomically and written via open file") || !strings.Contains(releaseDoc, "descriptors to reduce path-swap race windows") {
		t.Fatal("RELEASE.md should document atomic descriptor-backed release script outputs")
	}
	if !strings.Contains(releaseDoc, "Staged temporary evidence/SARIF files are also removed") || !strings.Contains(releaseDoc, "collides with an existing destination path") {
		t.Fatal("RELEASE.md should document staged-temp collision cleanup behavior")
	}
	if !strings.Contains(releaseDoc, "keep failing build artifacts for") || !strings.Contains(releaseDoc, "skip subsequent vuln/cleanup steps") {
		t.Fatal("RELEASE.md should document failure-artifact retention and skip behavior")
	}
	if !strings.Contains(releaseDoc, "RC_CLEANUP_REMOVE_FAILED") {
		t.Fatal("RELEASE.md should document cleanup failure machine-readable error code")
	}
	if !strings.Contains(releaseDoc, "RC_CLEANUP_REMOVE_FAILED_SUMMARY") {
		t.Fatal("RELEASE.md should document cleanup failure summary machine-readable error code")
	}
	if !strings.Contains(releaseDoc, "fail closed when git `HEAD` commit SHA cannot be resolved") ||
		!strings.Contains(releaseDoc, "canonical lowercase 40-hex") {
		t.Fatal("RELEASE.md should document fail-closed canonical git HEAD commit SHA requirement for evidence scripts")
	}
	if !strings.Contains(releaseDoc, "| Release-check code | Typical trigger |") {
		t.Fatal("RELEASE.md should include release-check machine-readable code table")
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
		"make release-evidence-offline",
		"make release-evidence-online",
		"inspect-sarif smoke generation, and govulncheck",
		"BUILD_OUT=.cache/gokui-release-evidence",
		".cache/gokui-release-check",
		"clean that artifact automatically",
		"validates output-path safety preflight checks before running",
		"fails closed when build/SARIF output paths include symlink",
		"build and SARIF outputs",
		"resolve to the same path",
		"RC_PREFLIGHT_BUILD_OUT_INVALID",
		"RC_PREFLIGHT_SARIF_OUT_INVALID",
		"RC_PREFLIGHT_BUILD_OUT_SYMLINK",
		"RC_PREFLIGHT_SARIF_OUT_SYMLINK",
		"RC_PREFLIGHT_OUTPUT_PATH_CONFLICT",
		"RC_PREFLIGHT_BUILD_OUT_EXISTS",
		"RC_PREFLIGHT_SARIF_OUT_EXISTS",
		"non-root file paths",
		"under the repository root",
		"directory-like paths ending with `/`",
		"located under `.git/`",
		"must not contain `.` or `..` path",
		"must not contain empty path segments",
		"must end with `.sarif`",
		"inspect-sarif` output paths must resolve under the repository root",
		"must resolve outside `.git/`",
		"must not contain `..` path segments",
		"must not contain `.` path segments",
		"must not contain empty path segments",
		"must be non-directory file paths",
		"must end with `.sarif`",
		"fail closed when repository-root/output/log paths include",
		"when expected output/log files already exist",
		"created atomically and written via open file",
		"descriptors to reduce path-swap race windows",
		"Staged temporary evidence/SARIF files are also removed",
		"collides with an existing destination path",
		"keep failing build artifacts",
		"for investigation and skip subsequent vuln/cleanup steps",
		"RC_CLEANUP_REMOVE_FAILED",
		"RC_CLEANUP_REMOVE_FAILED_SUMMARY",
		"fail closed when git `HEAD` commit SHA cannot be",
		"canonical lowercase 40-hex",
		"`Automation Error Codes` -> `release-check`",
		"git status --short",
		"-offline-audit.md",
		"-online-audit.md",
	}
	for _, line := range required {
		if !strings.Contains(readme, line) {
			t.Fatalf("README missing release-check documentation line: %q", line)
		}
	}
}

func TestReleaseCheckErrorCodeTableSyncBetweenReadmeAndReleaseDocs(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	releaseBytes, err := os.ReadFile("../../RELEASE.md")
	if err != nil {
		t.Fatalf("failed to read RELEASE.md: %v", err)
	}

	readmeCodes := extractReleaseCheckErrorCodesFromReadmeAutomationSection(t, string(readmeBytes))
	releaseCodes := extractReleaseCheckErrorCodesFromTable(t, string(releaseBytes), "RELEASE.md")

	readmeJoined := strings.Join(readmeCodes, ",")
	releaseJoined := strings.Join(releaseCodes, ",")
	if readmeJoined != releaseJoined {
		t.Fatalf("release-check code table mismatch between README.md and RELEASE.md\nREADME:  %s\nRELEASE: %s", readmeJoined, releaseJoined)
	}
}

func extractReleaseCheckErrorCodesFromTable(t *testing.T, doc, label string) []string {
	t.Helper()

	const tableHeader = "| Release-check code | Typical trigger |"
	start := strings.Index(doc, tableHeader)
	if start < 0 {
		t.Fatalf("%s missing release-check code table header", label)
	}
	section := doc[start:]
	lines := strings.Split(section, "\n")

	var builder strings.Builder
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			break
		}
		builder.WriteString(line)
		builder.WriteByte('\n')
	}
	return extractReleaseCheckErrorCodesFromText(t, builder.String(), label+" release-check code table")
}

func extractReleaseCheckErrorCodesFromReadmeAutomationSection(t *testing.T, readme string) []string {
	t.Helper()

	const sectionStart = "### release-check (`make release-check`, stderr codes)"
	start := strings.Index(readme, sectionStart)
	if start < 0 {
		t.Fatal("README.md missing release-check automation error code section")
	}
	section := readme[start:]
	sectionEnd := strings.Index(section, "\n## ")
	if sectionEnd > 0 {
		section = section[:sectionEnd]
	}
	return extractReleaseCheckErrorCodesFromText(t, section, "README.md release-check automation error code section")
}

func extractReleaseCheckErrorCodesFromAgents(t *testing.T, agents string) []string {
	t.Helper()

	const sectionStart = "Release-check machine-readable error codes are part of the current operational"
	start := strings.Index(agents, sectionStart)
	if start < 0 {
		t.Fatal("AGENTS.md missing release-check machine-readable error code section")
	}
	section := agents[start:]
	sectionEnd := strings.Index(section, "\n## ")
	if sectionEnd > 0 {
		section = section[:sectionEnd]
	}
	return extractReleaseCheckErrorCodesFromText(t, section, "AGENTS.md release-check machine-readable code section")
}

func extractReleaseCheckErrorCodesFromRoadmap(t *testing.T, roadmap string) []string {
	t.Helper()

	const sectionStart = "- release-check machine-readable error code set for automation routing"
	start := strings.Index(roadmap, sectionStart)
	if start < 0 {
		t.Fatal("ROADMAP.md missing release-check machine-readable error code set line")
	}
	section := roadmap[start:]
	lineEnd := strings.Index(section, "\n")
	if lineEnd > 0 {
		section = section[:lineEnd]
	}
	return extractReleaseCheckErrorCodesFromText(t, section, "ROADMAP.md release-check machine-readable code set line")
}

func extractReleaseCheckErrorCodesFromText(t *testing.T, text, label string) []string {
	t.Helper()
	codeRe := regexp.MustCompile("`(RC_[A-Z0-9_]+)`")
	matches := codeRe.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		t.Fatalf("%s has no RC_* entries", label)
	}

	codes := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		codes[m[1]] = struct{}{}
	}
	out := make([]string, 0, len(codes))
	for code := range codes {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

func TestLocalBuildArtifactIgnoreSync(t *testing.T) {
	gitignoreBytes, err := os.ReadFile("../../.gitignore")
	if err != nil {
		t.Fatalf("failed to read .gitignore: %v", err)
	}
	gitignore := string(gitignoreBytes)
	if !strings.Contains(gitignore, "gokui") {
		t.Fatal(".gitignore should ignore local gokui build artifact")
	}

	releaseBytes, err := os.ReadFile("../../RELEASE.md")
	if err != nil {
		t.Fatalf("failed to read RELEASE.md: %v", err)
	}
	releaseDoc := string(releaseBytes)
	if !strings.Contains(releaseDoc, "ignored as a local build artifact") {
		t.Fatal("RELEASE.md should document gokui local-build ignore behavior")
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
		"BUILD_OUT ?= gokui",
		"RELEASE_CHECK_BUILD_OUT ?= $(CACHE_DIR)/gokui-release-check",
		"RELEASE_CHECK_SARIF_OUT ?= $(CACHE_DIR)/inspect-results.sarif",
		"RELEASE_CHECK_BUILD_OUT_ABS := $(abspath $(RELEASE_CHECK_BUILD_OUT))",
		"RELEASE_CHECK_SARIF_OUT_ABS := $(abspath $(RELEASE_CHECK_SARIF_OUT))",
		"MAKEFILE_DIR_ABS := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))",
		"RELEASE_CHECK_GIT_DIR_ABS := $(MAKEFILE_DIR_ABS)/.git",
		"RELEASE_CHECK_REPO_ROOT_ABS := $(MAKEFILE_DIR_ABS)",
		"release-check-preflight:",
		"release-check: release-check-preflight",
		"$(MAKE) check; \\",
		"$(MAKE) test; \\",
		"$(MAKE) test-race; \\",
		"cleanup_release_check_outputs() {",
		`for output_path in "$(RELEASE_CHECK_BUILD_OUT_ABS)" "$(RELEASE_CHECK_SARIF_OUT_ABS)"; do \`,
		`echo "[RC_CLEANUP_REMOVE_FAILED] release-check cleanup failed for output path: $$output_path" >&2; \`,
		`echo "[RC_CLEANUP_REMOVE_FAILED_SUMMARY] release-check cleanup failed for $$failed_count output path(s)" >&2; \`,
		"emit_preflight_error() {",
		`echo "[$$code] $$message" >&2; \`,
		"assert_no_symlink_components() {",
		"assert_no_empty_segments() {",
		"assert_no_dot_segments() {",
		"assert_sarif_extension() {",
		"assert_under_repo_root() {",
		"assert_not_git_path() {",
		`assert_no_empty_segments "$(RELEASE_CHECK_BUILD_OUT)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_INVALID"; \`,
		`assert_no_empty_segments "$(RELEASE_CHECK_SARIF_OUT)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \`,
		`assert_no_dot_segments "$(RELEASE_CHECK_BUILD_OUT)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_INVALID"; \`,
		`assert_no_dot_segments "$(RELEASE_CHECK_SARIF_OUT)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \`,
		`assert_sarif_extension "$(RELEASE_CHECK_SARIF_OUT)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \`,
		`assert_under_repo_root "$(RELEASE_CHECK_BUILD_OUT_ABS)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_INVALID"; \`,
		`assert_under_repo_root "$(RELEASE_CHECK_SARIF_OUT_ABS)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \`,
		`assert_not_git_path "$(RELEASE_CHECK_BUILD_OUT_ABS)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_INVALID"; \`,
		`assert_not_git_path "$(RELEASE_CHECK_SARIF_OUT_ABS)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \`,
		`assert_no_symlink_components "$(RELEASE_CHECK_BUILD_OUT_ABS)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_SYMLINK"; \`,
		`assert_no_symlink_components "$(RELEASE_CHECK_SARIF_OUT_ABS)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_SYMLINK"; \`,
		`case "$(RELEASE_CHECK_BUILD_OUT)" in ""|"/"|"."|*/) \`,
		`case "$(RELEASE_CHECK_SARIF_OUT)" in ""|"/"|"."|*/) \`,
		`emit_preflight_error "RC_PREFLIGHT_BUILD_OUT_INVALID" "release-check build output path must be a non-root file path"; \`,
		`emit_preflight_error "RC_PREFLIGHT_SARIF_OUT_INVALID" "release-check SARIF output path must be a non-root file path"; \`,
		`emit_preflight_error "RC_PREFLIGHT_OUTPUT_PATH_CONFLICT" "release-check build and SARIF outputs must be different paths: build=$(RELEASE_CHECK_BUILD_OUT_ABS) sarif=$(RELEASE_CHECK_SARIF_OUT_ABS)"; \`,
		`emit_preflight_error "RC_PREFLIGHT_BUILD_OUT_EXISTS" "release-check build output already exists: $(RELEASE_CHECK_BUILD_OUT_ABS)"; \`,
		`emit_preflight_error "RC_PREFLIGHT_SARIF_OUT_EXISTS" "release-check SARIF output already exists: $(RELEASE_CHECK_SARIF_OUT_ABS)"; \`,
		`if [ -e "$(RELEASE_CHECK_BUILD_OUT_ABS)" ]; then \`,
		`if [ -e "$(RELEASE_CHECK_SARIF_OUT_ABS)" ]; then \`,
		"$(GO) build -trimpath -buildvcs=true -ldflags='$(LDFLAGS)' -o $(BUILD_OUT) $(MAIN_PKG)",
		"$(MAKE) build BUILD_OUT=$(RELEASE_CHECK_BUILD_OUT_ABS)",
		`trap 'cleanup_release_check_outputs' EXIT; \`,
		"GOTOOLCHAIN=$(VULN_GOTOOLCHAIN) $(GO) tool govulncheck ./...",
		"release-evidence-offline:",
		"./scripts/collect-release-evidence.sh",
		"release-evidence-online:",
		"./scripts/collect-release-evidence.sh --with-vuln",
	}
	for _, line := range required {
		if !strings.Contains(makefile, line) {
			t.Fatalf("Makefile missing vuln toolchain baseline line: %q", line)
		}
	}
}

func TestReleaseEvidenceModeNamingDocumentationSync(t *testing.T) {
	scriptBytes, err := os.ReadFile("../../scripts/collect-release-evidence.sh")
	if err != nil {
		t.Fatalf("failed to read collect-release-evidence.sh: %v", err)
	}
	script := string(scriptBytes)
	scriptRequired := []string{
		`AUDIT_KIND="offline-audit"`,
		`AUDIT_KIND="online-audit"`,
		`BASENAME="${TS}-${COMMIT_SHA}-${AUDIT_KIND}"`,
	}
	for _, line := range scriptRequired {
		if !strings.Contains(script, line) {
			t.Fatalf("collect-release-evidence.sh missing mode naming line: %q", line)
		}
	}

	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	if !strings.Contains(readme, "`-offline-audit.md` or") || !strings.Contains(readme, "`-online-audit.md`") {
		t.Fatal("README.md should document offline/online evidence filename suffixes")
	}

	releaseBytes, err := os.ReadFile("../../RELEASE.md")
	if err != nil {
		t.Fatalf("failed to read RELEASE.md: %v", err)
	}
	releaseDoc := string(releaseBytes)
	if !strings.Contains(releaseDoc, "`-offline-audit.md` or `-online-audit.md`") {
		t.Fatal("RELEASE.md should document offline/online evidence filename suffixes")
	}
}

func TestInspectSARIFScriptHardeningSync(t *testing.T) {
	scriptBytes, err := os.ReadFile("../../scripts/generate-inspect-sarif.sh")
	if err != nil {
		t.Fatalf("failed to read generate-inspect-sarif.sh: %v", err)
	}
	script := string(scriptBytes)

	required := []string{
		"set -o noclobber",
		"umask 077",
		"assert_no_symlink_components()",
		"create_temp_file_for_write()",
		`tmp_path="$(mktemp "$dir/.${base}.tmp.XXXXXX")"`,
		`exec {fd}>>"$tmp_path"`,
		`assert_no_symlink_components "$ROOT_DIR" "repository root path"`,
		`if [[ "$out_path" != /* ]]; then`,
		`out_path="$ROOT_DIR/$out_path"`,
		`out_dir="$(dirname "$out_path")"`,
		`assert_sarif_output_extension()`,
		`assert_sarif_output_extension "$out_path" "inspect SARIF output path"`,
		`assert_no_empty_segments()`,
		`assert_no_empty_segments "$out_path" "inspect SARIF output path"`,
		`assert_no_dot_segments()`,
		`assert_no_dot_segments "$out_path" "inspect SARIF output path"`,
		`assert_non_directory_file_path()`,
		`assert_non_directory_file_path "$out_path" "inspect SARIF output path"`,
		`assert_no_dotdot_segments()`,
		`assert_no_dotdot_segments "$out_path" "inspect SARIF output path"`,
		`assert_under_repo_root()`,
		`assert_under_repo_root "$out_path" "inspect SARIF output path"`,
		`assert_not_git_path()`,
		`assert_not_git_path "$out_path" "inspect SARIF output path"`,
		`assert_no_symlink_components "$out_dir" "inspect SARIF output directory"`,
		`assert_no_symlink_components "$out_path" "inspect SARIF output path"`,
		`if [ -e "$out_path" ]; then`,
		`mkdir -p "$out_dir"`,
		`create_temp_file_for_write "$out_dir" "$out_base" TMP_SARIF_PATH SARIF_FD`,
		`"$tmp_bin" inspect "$ROOT_DIR/fixtures/fake-prereq-skill" --format sarif >&"$SARIF_FD"`,
		`grep -q '"version": "2.1.0"' "$TMP_SARIF_PATH"`,
		`grep -q '"FAKE_PREREQ_EXECUTION"' "$TMP_SARIF_PATH"`,
		`mv -n "$TMP_SARIF_PATH" "$out_path"`,
		`rm -f -- "$TMP_SARIF_PATH"`,
		`exec {SARIF_FD}>&-`,
	}
	for _, line := range required {
		if !strings.Contains(script, line) {
			t.Fatalf("generate-inspect-sarif.sh missing hardening line: %q", line)
		}
	}

	outDirCheck := strings.Index(script, `assert_no_symlink_components "$out_dir" "inspect SARIF output directory"`)
	mkdirLine := strings.Index(script, `mkdir -p "$out_dir"`)
	if outDirCheck == -1 || mkdirLine == -1 {
		t.Fatal("generate-inspect-sarif.sh should include output directory symlink check and mkdir")
	}
	if outDirCheck > mkdirLine {
		t.Fatal("generate-inspect-sarif.sh should reject symlinked output directory before mkdir -p")
	}
}

func TestReleaseEvidenceScriptExecutionContractSync(t *testing.T) {
	scriptBytes, err := os.ReadFile("../../scripts/collect-release-evidence.sh")
	if err != nil {
		t.Fatalf("failed to read collect-release-evidence.sh: %v", err)
	}
	script := string(scriptBytes)

	required := []string{
		"set -o noclobber",
		"umask 077",
		"assert_no_symlink_components()",
		"create_temp_file_for_write()",
		"assert_output_path_available()",
		`tmp_path="$(mktemp "$dir/.${base}.tmp.XXXXXX")"`,
		`exec {fd}>>"$tmp_path"`,
		`assert_no_symlink_components "$ROOT_DIR" "repository root path"`,
		`EVIDENCE_MODE="offline"`,
		`EVIDENCE_MODE="online"`,
		`assert_no_symlink_components "$OUT_DIR" "evidence directory"`,
		`assert_no_symlink_components "$LOG_DIR" "evidence log directory"`,
		`resolve_commit_sha()`,
		`git -C "$ROOT_DIR" rev-parse HEAD`,
		`COMMIT_SHA="$(resolve_commit_sha)"`,
		`git HEAD commit SHA must be lowercase 40-hex`,
		`assert_output_path_available "$OUT_PATH" "evidence path"`,
		`create_temp_file_for_write "$OUT_DIR" "$OUT_BASENAME" TMP_EVIDENCE_PATH EVIDENCE_FD`,
		`assert_output_path_available "$log_path" "log path"`,
		`create_temp_file_for_write "$LOG_DIR" "$log_basename" tmp_log_path log_fd`,
		`echo "- Mode: ${EVIDENCE_MODE}"`,
		`git status --short`,
		`BUILD_OUT=\"$ROOT_DIR/.cache/gokui-release-evidence\" make release-check-offline`,
		`if [ "$WITH_VULN" -eq 1 ] && [ "$FAILED_STEPS" -eq 0 ]; then`,
		`if [ "$FAILED_STEPS" -eq 0 ]; then`,
		"preserve failing build artifact for investigation",
		`cleanup evidence build artifact`,
		`rm -f -- \"$ROOT_DIR/.cache/gokui-release-evidence\"`,
		`mv -n "$tmp_log_path" "$log_path"`,
		`mv -n "$TMP_EVIDENCE_PATH" "$OUT_PATH"`,
		`rm -f -- "$tmp_log_path"`,
		`rm -f -- "$TMP_EVIDENCE_PATH"`,
		`exec {EVIDENCE_FD}>&-`,
	}
	for _, line := range required {
		if !strings.Contains(script, line) {
			t.Fatalf("collect-release-evidence.sh missing execution contract line: %q", line)
		}
	}

	outDirCheck := strings.Index(script, `assert_no_symlink_components "$OUT_DIR" "evidence directory"`)
	logDirCheck := strings.Index(script, `assert_no_symlink_components "$LOG_DIR" "evidence log directory"`)
	mkdirLine := strings.Index(script, `mkdir -p "$OUT_DIR" "$LOG_DIR"`)
	if outDirCheck == -1 || logDirCheck == -1 || mkdirLine == -1 {
		t.Fatal("collect-release-evidence.sh should include OUT_DIR/LOG_DIR symlink checks and mkdir")
	}
	if outDirCheck > mkdirLine || logDirCheck > mkdirLine {
		t.Fatal("collect-release-evidence.sh should reject symlinked OUT_DIR/LOG_DIR before mkdir -p")
	}
	if strings.Contains(script, `COMMIT_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"`) {
		t.Fatal("collect-release-evidence.sh should fail closed when git HEAD commit cannot be resolved")
	}
}

func TestReleaseEvidenceTemplateScriptHardeningSync(t *testing.T) {
	scriptBytes, err := os.ReadFile("../../scripts/new-release-evidence.sh")
	if err != nil {
		t.Fatalf("failed to read new-release-evidence.sh: %v", err)
	}
	script := string(scriptBytes)

	required := []string{
		"set -o noclobber",
		"umask 077",
		"assert_no_symlink_components()",
		"create_temp_file_for_write()",
		"assert_output_path_available()",
		`tmp_path="$(mktemp "$dir/.${base}.tmp.XXXXXX")"`,
		`exec {fd}>>"$tmp_path"`,
		`assert_no_symlink_components "$ROOT_DIR" "repository root path"`,
		`assert_no_symlink_components "$TEMPLATE_PATH" "release evidence template path"`,
		`assert_no_symlink_components "$OUT_DIR" "release evidence output directory"`,
		`resolve_commit_sha()`,
		`git -C "$ROOT_DIR" rev-parse HEAD`,
		`COMMIT_SHA="$(resolve_commit_sha)"`,
		`git HEAD commit SHA must be lowercase 40-hex`,
		`assert_output_path_available "$OUT_PATH" "release evidence output path"`,
		`create_temp_file_for_write "$OUT_DIR" "$OUT_BASENAME" TMP_EVIDENCE_PATH EVIDENCE_FD`,
		`mv -n "$TMP_EVIDENCE_PATH" "$OUT_PATH"`,
		`rm -f -- "$TMP_EVIDENCE_PATH"`,
		`exec {EVIDENCE_FD}>&-`,
	}
	for _, line := range required {
		if !strings.Contains(script, line) {
			t.Fatalf("new-release-evidence.sh missing hardening line: %q", line)
		}
	}
	if strings.Contains(script, `COMMIT_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"`) {
		t.Fatal("new-release-evidence.sh should fail closed when git HEAD commit cannot be resolved")
	}
}

func TestGitignoreReleaseEvidenceArtifactsSync(t *testing.T) {
	gitignoreBytes, err := os.ReadFile("../../.gitignore")
	if err != nil {
		t.Fatalf("failed to read .gitignore: %v", err)
	}
	gitignore := string(gitignoreBytes)
	if !strings.Contains(gitignore, "releases/evidence/") {
		t.Fatal(".gitignore should ignore generated release evidence artifacts")
	}
}

func TestRoadmapRuleIDsAreImplemented(t *testing.T) {
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	rowPattern := regexp.MustCompile(`\| ` + "`" + `([A-Z0-9_]+)` + "`" + ` \|`)
	matches := rowPattern.FindAllStringSubmatch(roadmap, -1)
	if len(matches) == 0 {
		t.Fatal("ROADMAP.md rule table rows not found")
	}

	implFiles := []string{
		"../../internal/scan/scan.go",
		"../../internal/materialize/archive.go",
		"../../internal/app/app.go",
	}
	var implText strings.Builder
	for _, path := range implFiles {
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("failed to read implementation file %s: %v", path, readErr)
		}
		implText.WriteString(string(b))
		implText.WriteByte('\n')
	}
	impl := implText.String()

	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		id := m[1]
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if !strings.Contains(impl, `"`+id+`"`) {
			t.Fatalf("ROADMAP rule ID %q is not implemented in core sources", id)
		}
	}
}

func TestRoadmapReleaseEvidenceHardeningSync(t *testing.T) {
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	required := []string{
		"automated offline release evidence collection with per-step logs",
		"automated online release evidence collection mode (includes vuln step)",
		"release-evidence template path/output hardening (symlink path-component rejection, restrictive template-output file permissions, and staged temporary output finalized atomically)",
		"release-evidence output/log path hardening (symlink path-component rejection, restrictive evidence/log file permissions, fail-closed output/log collision checks, staged temporary evidence/log outputs finalized atomically with collision cleanup, descriptor-backed writes, and failure-artifact retention)",
		"release-evidence commit provenance hardening (fail-closed git `HEAD` resolution with canonical lowercase 40-hex commit SHA enforcement)",
		"inspect-sarif output path hardening (repository-root-only and outside-`.git` output enforcement, `.sarif` extension enforcement, non-directory file-path enforcement including trailing `/.`/`/..` rejection, empty/`.`/`..` path-segment rejection, symlink path-component rejection, restrictive SARIF file permissions, fail-closed output-collision checks, and atomic file creation with descriptor-backed writes)",
		"release script repository-root path hardening (reject symlinked repository-root execution paths)",
		"release-evidence gate hardening with isolated build output (`BUILD_OUT`) and tracked/untracked clean-tree checks (`git status --short`)",
		"release-check gate hardening with isolated build output (`RELEASE_CHECK_BUILD_OUT`), preflight-first execution ordering, absolute-path preflight normalization, symlink/collision fail-closed build/SARIF output guards (including non-root-path, `.sarif` extension enforcement for SARIF output, empty/`.`/`..` path-segment rejection, repository-root-only outputs, `.git` path rejection, and distinct-path enforcement), machine-readable preflight/cleanup error codes, and failure-safe cleanup for build/SARIF artifacts",
		"release-evidence metadata mode annotation (`offline|online`) and mode-specific evidence filename suffixes (`-offline-audit.md` / `-online-audit.md`)",
	}
	for _, line := range required {
		if !strings.Contains(roadmap, line) {
			t.Fatalf("ROADMAP.md missing release-evidence hardening line: %q", line)
		}
	}
}

func TestReadmePolicyExampleSchemaSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)

	required := []string{
		"## Policy Profiles",
		"[profiles.strict]",
		"[profiles.team]",
		"[profiles.research]",
		"reject_severities = [\"critical\", \"high\"]",
		"[overrides]",
		"allowed_rule_ids = [",
	}
	for _, line := range required {
		if !strings.Contains(readme, line) {
			t.Fatalf("README missing policy example line: %q", line)
		}
	}

	disallowed := []string{
		"[profile.strict]",
		"[profile.team]",
		"[profile.research]",
		"allow_scripts = ",
		"on_high = ",
		"on_medium = ",
		"on_critical = ",
	}
	for _, line := range disallowed {
		if strings.Contains(readme, line) {
			t.Fatalf("README policy example should not include deprecated/unsupported line: %q", line)
		}
	}
}
