package app

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

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
		"Evidence scripts inherit `GOCACHE`, `GOMODCACHE`, `GOPATH`, and",
		"`XDG_CACHE_HOME` when explicitly set",
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
		"must not include leading or trailing",
		"must not contain ASCII control",
		"must end with `.sarif`",
		"inspect-sarif` output paths must resolve under the repository root",
		"must resolve outside `.git/`",
		"must not contain `..` path segments",
		"must not contain `.` path segments",
		"must not contain empty path segments",
		"must not include leading or trailing whitespace",
		"must not contain ASCII control characters",
		"must be non-empty",
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
