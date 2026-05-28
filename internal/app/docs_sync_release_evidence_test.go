package app

import (
	"os"
	"strings"
	"testing"
)

func TestBetaReleaseTrackDocumentationSync(t *testing.T) {
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

	requiredReadme := []string{
		"make beta-check",
		"make release-evidence-beta",
		"make release-evidence-beta-selfcheck",
		"make beta-ready",
		".cache/gokui-beta-check",
		".cache/inspect-results-beta-check.sarif",
		"`-beta-audit.md` suffix",
		"do not combine `--beta` and",
		"`--with-vuln`",
		"`git status --short` must be empty",
	}
	for _, line := range requiredReadme {
		if !strings.Contains(readme, line) {
			t.Fatalf("README missing beta release track line: %q", line)
		}
	}

	requiredRoadmap := []string{
		"## Beta Release Track (Current Priority)",
		"`make beta-check`",
		"`make release-evidence-beta`",
		"`README.md`, `ROADMAP.md`, and `RELEASE.md` are consistent.",
	}
	for _, line := range requiredRoadmap {
		if !strings.Contains(roadmap, line) {
			t.Fatalf("ROADMAP missing beta release track line: %q", line)
		}
	}

	requiredRelease := []string{
		"## 3) Beta Fast Path",
		"make beta-check",
		"make release-evidence-beta",
		"make release-evidence-beta-selfcheck",
		"make beta-ready",
		"`-beta-audit.md` evidence file",
		"Beta evidence mode is offline-only and does not allow `--with-vuln`.",
		"`git status --short` must be empty",
	}
	for _, line := range requiredRelease {
		if !strings.Contains(releaseDoc, line) {
			t.Fatalf("RELEASE missing beta release track line: %q", line)
		}
	}
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
	if !strings.Contains(gitignore, "releases/beta/") {
		t.Fatal(".gitignore should ignore local beta release artifact staging directory")
	}

	releaseBytes, err := os.ReadFile("../../RELEASE.md")
	if err != nil {
		t.Fatalf("failed to read RELEASE.md: %v", err)
	}
	releaseDoc := string(releaseBytes)
	if !strings.Contains(releaseDoc, "ignored as a local build artifact") {
		t.Fatal("RELEASE.md should document gokui local-build ignore behavior")
	}
	if !strings.Contains(releaseDoc, "`releases/beta/` is ignored") {
		t.Fatal("RELEASE.md should document local beta release artifact ignore behavior")
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

func TestGitignoreReleaseEvidenceArtifactsSync(t *testing.T) {
	gitignoreBytes, err := os.ReadFile("../../.gitignore")
	if err != nil {
		t.Fatalf("failed to read .gitignore: %v", err)
	}
	gitignore := string(gitignoreBytes)
	if !strings.Contains(gitignore, "releases/evidence/") {
		t.Fatal(".gitignore should ignore generated release evidence artifacts")
	}
	if !strings.Contains(gitignore, "releases/beta/") {
		t.Fatal(".gitignore should ignore generated local beta release staging artifacts")
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
		"inspect-sarif output path hardening (repository-root-only and outside-`.git` output enforcement, `.sarif` extension enforcement, non-empty-path enforcement, leading/trailing whitespace rejection, ASCII control-character rejection, non-directory file-path enforcement including trailing `/.`/`/..` rejection, empty/`.`/`..` path-segment rejection, symlink path-component rejection, restrictive SARIF file permissions, fail-closed output-collision checks, and atomic file creation with descriptor-backed writes)",
		"release script repository-root path hardening (reject symlinked repository-root execution paths)",
		"release-evidence gate hardening with isolated build output (`BUILD_OUT`) and tracked/untracked clean-tree checks (`git status --short`)",
		"release-check gate hardening with isolated build output (`RELEASE_CHECK_BUILD_OUT`), preflight-first execution ordering, absolute-path preflight normalization, symlink/collision fail-closed build/SARIF output guards (including non-root-path, `.sarif` extension enforcement for SARIF output, leading/trailing whitespace rejection, ASCII control-character rejection, empty/`.`/`..` path-segment rejection, repository-root-only outputs, `.git` path rejection, and distinct-path enforcement), machine-readable preflight/cleanup error codes, and failure-safe cleanup for build/SARIF artifacts",
		"release-evidence metadata mode annotation (`offline|online`) and mode-specific evidence filename suffixes (`-offline-audit.md` / `-online-audit.md`)",
	}
	for _, line := range required {
		if !strings.Contains(roadmap, line) {
			t.Fatalf("ROADMAP.md missing release-evidence hardening line: %q", line)
		}
	}
}
