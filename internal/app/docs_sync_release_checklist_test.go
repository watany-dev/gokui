package app

import (
	"os"
	"strings"
	"testing"
)

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
		"make release-evidence-beta-selfcheck",
		"make beta-ready",
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
	if !strings.Contains(releaseDoc, "inherit `GOCACHE`, `GOMODCACHE`, `GOPATH`, and") ||
		!strings.Contains(releaseDoc, "`XDG_CACHE_HOME` from the environment") {
		t.Fatal("RELEASE.md should document environment-cache override behavior for evidence scripts")
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
		!strings.Contains(releaseDoc, "must not include leading or trailing") ||
		!strings.Contains(releaseDoc, "must not contain ASCII control") ||
		!strings.Contains(releaseDoc, "must end with `.sarif`") {
		t.Fatal("RELEASE.md should document release-check non-root/repository-root/non-directory/.git/dot-segment/extension output path guards")
	}
	if !strings.Contains(releaseDoc, "make inspect-sarif") ||
		!strings.Contains(releaseDoc, "output paths must resolve under the repository root") ||
		!strings.Contains(releaseDoc, "must resolve outside `.git/`") ||
		!strings.Contains(releaseDoc, "must not contain `..` path segments") ||
		!strings.Contains(releaseDoc, "must not contain `.` path segments") ||
		!strings.Contains(releaseDoc, "must not contain empty path segments") ||
		!strings.Contains(releaseDoc, "must not include leading or trailing whitespace") ||
		!strings.Contains(releaseDoc, "must not contain ASCII control characters") ||
		!strings.Contains(releaseDoc, "must be non-empty") ||
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
