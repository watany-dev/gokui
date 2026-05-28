package app

import (
	"encoding/json"
	reportpkg "github.com/watany-dev/gokui/internal/report"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunUpdateJSONFatalErrors(t *testing.T) {
	t.Run("parse errors emit machine-readable JSON", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(json parse error) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json parse errors, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateFatalCodeArgsInvalid+"\"") {
			t.Fatalf("stdout should include parse error code, got %q", stdout.String())
		}
	})

	t.Run("target validation errors emit machine-readable JSON", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "unsupported-target", "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(json target invalid) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json target errors, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateFatalCodeTargetInvalid+"\"") {
			t.Fatalf("stdout should include target-invalid error code, got %q", stdout.String())
		}
	})

	t.Run("symlink target root emits machine-readable JSON", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		base := t.TempDir()
		realTarget := filepath.Join(base, "real-skills")
		if err := os.Mkdir(realTarget, 0o755); err != nil {
			t.Fatalf("mkdir real target: %v", err)
		}
		symlinkTarget := filepath.Join(base, "skills-link")
		if err := os.Symlink("real-skills", symlinkTarget); err != nil {
			t.Fatalf("create target symlink: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + symlinkTarget, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(json target symlink) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json target errors, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateFatalCodeTargetInvalid+"\"") {
			t.Fatalf("stdout should include target-invalid error code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+rulepkg.UpdateTargetSymlink.ID+"\"") {
			t.Fatalf("stdout should include symlink rule_id, got %q", stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runUpdate([]string{"--dry-run", "--target", "custom:" + symlinkTarget}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(human target symlink) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty for human target errors, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), rulepkg.UpdateTargetSymlink.ID) {
			t.Fatalf("stderr should include symlink rule marker, got %q", stderr.String())
		}
	})

	t.Run("target read failures emit machine-readable JSON", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + filepath.Join(t.TempDir(), "missing"), "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(json target read fail) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json build errors, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateFatalCodeTargetReadFail+"\"") {
			t.Fatalf("stdout should include target-read-failed code, got %q", stdout.String())
		}
	})

	t.Run("policy load failure emits machine-readable JSON", func(t *testing.T) {
		policyPath := filepath.Join(t.TempDir(), "policy.toml")
		if err := os.WriteFile(policyPath, []byte("default_profile = ["), 0o644); err != nil {
			t.Fatalf("write policy file: %v", err)
		}
		t.Setenv("GOKUI_POLICY_PATH", policyPath)

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + filepath.Join(t.TempDir(), "missing"), "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(json policy load fail) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json policy load errors, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateFatalCodePolicyLoadFail+"\"") {
			t.Fatalf("stdout should include policy-load-failed code, got %q", stdout.String())
		}
	})

	t.Run("symlink entry under target emits report-build rule_id", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		src := createSkillSourceForInstallTest(t, "target-entry-symlink-neighbor")
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source:        source{Input: src, Kind: "local-dir"},
			PolicyProfile: "strict",
			Decision:      "PASS",
		}
		installedPath, _, err := installSkillAtomic(src, targetRoot, "target-entry-symlink-neighbor", report)
		if err != nil {
			t.Fatalf("installSkillAtomic() error = %v", err)
		}
		if err := os.Mkdir(filepath.Join(targetRoot, "real-entry"), 0o755); err != nil {
			t.Fatalf("mkdir real entry: %v", err)
		}
		if err := os.Symlink("real-entry", filepath.Join(targetRoot, "link-entry")); err != nil {
			t.Fatalf("create entry symlink: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(json target entry symlink) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json build errors, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateFatalCodeReportBuild+"\"") {
			t.Fatalf("stdout should include report-build error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+rulepkg.UpdateTargetEntrySymlink.ID+"\"") {
			t.Fatalf("stdout should include target-entry symlink rule_id, got %q", stdout.String())
		}

		// Even when update fails on symlink entry, neighboring valid install must remain verified.
		lockState, err := verifyLock(installedPath)
		if err != nil {
			t.Fatalf("verifyLock() error = %v", err)
		}
		if lockState.Status != "VERIFIED" {
			t.Fatalf("lock status after target-entry symlink error = %q, want VERIFIED", lockState.Status)
		}
		if len(lockState.Drift.MissingFiles) != 0 || len(lockState.Drift.ChangedFiles) != 0 || len(lockState.Drift.UnexpectedFiles) != 0 {
			t.Fatalf("unexpected drift after target-entry symlink error: %+v", lockState.Drift)
		}
	})
}

func TestRunUpdateSARIFFatalErrors(t *testing.T) {
	t.Run("parse errors emit machine-readable SARIF", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--format", "sarif"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(sarif parse error) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif parse errors, got %q", stderr.String())
		}
		var sarif reportpkg.SARIFDocument
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
			t.Fatalf("unexpected sarif structure: %+v", sarif)
		}
		if sarif.Runs[0].Results[0].RuleID != updateFatalCodeArgsInvalid {
			t.Fatalf("rule id = %q, want %q", sarif.Runs[0].Results[0].RuleID, updateFatalCodeArgsInvalid)
		}
		if sarif.Runs[0].Invocations[0].ExecutionSuccessful {
			t.Fatal("sarif parse-error invocation should be unsuccessful")
		}
	})

	t.Run("target read failures emit machine-readable SARIF", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + filepath.Join(t.TempDir(), "missing"), "--format", "sarif"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(sarif target read fail) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif build errors, got %q", stderr.String())
		}
		var sarif reportpkg.SARIFDocument
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
			t.Fatalf("unexpected sarif structure: %+v", sarif)
		}
		if sarif.Runs[0].Results[0].RuleID != updateFatalCodeTargetReadFail {
			t.Fatalf("rule id = %q, want %q", sarif.Runs[0].Results[0].RuleID, updateFatalCodeTargetReadFail)
		}
		if sarif.Runs[0].Properties.Decision != "ERROR" {
			t.Fatalf("decision = %q, want ERROR", sarif.Runs[0].Properties.Decision)
		}
	})

	t.Run("policy load failure emits machine-readable SARIF", func(t *testing.T) {
		policyPath := filepath.Join(t.TempDir(), "policy.toml")
		if err := os.WriteFile(policyPath, []byte("default_profile = ["), 0o644); err != nil {
			t.Fatalf("write policy file: %v", err)
		}
		t.Setenv("GOKUI_POLICY_PATH", policyPath)

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + filepath.Join(t.TempDir(), "missing"), "--format", "sarif"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(sarif policy load fail) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif policy load errors, got %q", stderr.String())
		}
		var sarif reportpkg.SARIFDocument
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
			t.Fatalf("unexpected sarif structure: %+v", sarif)
		}
		if sarif.Runs[0].Results[0].RuleID != updateFatalCodePolicyLoadFail {
			t.Fatalf("rule id = %q, want %q", sarif.Runs[0].Results[0].RuleID, updateFatalCodePolicyLoadFail)
		}
	})
}

func TestWriteUpdateJSONErrorRuleID(t *testing.T) {
	t.Run("infers rule_id from rule-prefixed message", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder

		code := writeUpdateJSONError(&stdout, &stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     updateFatalCodeReportBuild,
			Message:       "ARCHIVE_PATH_ESCAPE: archive entry escaped source root",
			Target:        "codex",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("writeUpdateJSONError() code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \"ARCHIVE_PATH_ESCAPE\"") {
			t.Fatalf("stdout should include inferred rule_id, got %q", stdout.String())
		}
	})

	t.Run("omits rule_id when message has no rule prefix", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder

		code := writeUpdateJSONError(&stdout, &stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     updateFatalCodeArgsInvalid,
			Message:       "update currently requires --dry-run",
			Target:        "codex",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("writeUpdateJSONError() code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if strings.Contains(stdout.String(), "\"rule_id\":") {
			t.Fatalf("stdout should omit rule_id, got %q", stdout.String())
		}
	})
}

func TestWriteUpdateSARIFErrorRuleID(t *testing.T) {
	t.Run("infers rule_id from rule-prefixed message", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder

		code := writeUpdateSARIFError(&stdout, &stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     updateFatalCodeReportBuild,
			Message:       "ARCHIVE_PATH_ESCAPE: archive entry escaped source root",
			Target:        "codex",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("writeUpdateSARIFError() code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		var sarif reportpkg.SARIFDocument
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
			t.Fatalf("unexpected sarif structure: %+v", sarif)
		}
		if sarif.Runs[0].Results[0].RuleID != "ARCHIVE_PATH_ESCAPE" {
			t.Fatalf("rule id = %q, want ARCHIVE_PATH_ESCAPE", sarif.Runs[0].Results[0].RuleID)
		}
	})

	t.Run("preserves explicit rule_id", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder

		code := writeUpdateSARIFError(&stdout, &stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     updateFatalCodeReportBuild,
			RuleID:        "EXPLICIT_RULE",
			Message:       "synthetic update error",
			Target:        "codex",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("writeUpdateSARIFError() code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		var sarif reportpkg.SARIFDocument
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
			t.Fatalf("unexpected sarif structure: %+v", sarif)
		}
		if sarif.Runs[0].Results[0].RuleID != "EXPLICIT_RULE" {
			t.Fatalf("rule id = %q, want EXPLICIT_RULE", sarif.Runs[0].Results[0].RuleID)
		}
	})
}

func TestUpdateArgJSONHelpers(t *testing.T) {
	if !updateArgsRequestJSON([]string{"--dry-run", "--format", "json"}) {
		t.Fatal("updateArgsRequestJSON() should detect --format json")
	}
	if !updateArgsRequestJSON([]string{"--dry-run", "--format=json"}) {
		t.Fatal("updateArgsRequestJSON() should detect --format=json")
	}
	if updateArgsRequestJSON([]string{"--dry-run", "--format", "human"}) {
		t.Fatal("updateArgsRequestJSON() should be false for non-json format")
	}
	if !updateArgsRequestSARIF([]string{"--dry-run", "--format", "sarif"}) {
		t.Fatal("updateArgsRequestSARIF() should detect --format sarif")
	}
	if !updateArgsRequestSARIF([]string{"--dry-run", "--format=sarif"}) {
		t.Fatal("updateArgsRequestSARIF() should detect --format=sarif")
	}
	if updateArgsRequestSARIF([]string{"--dry-run", "--format", "json"}) {
		t.Fatal("updateArgsRequestSARIF() should be false for non-sarif format")
	}
	if got := extractUpdateTargetArg([]string{"--dry-run", "--target", "custom:/tmp/skills"}); got != "custom:/tmp/skills" {
		t.Fatalf("extractUpdateTargetArg() = %q", got)
	}
	if got := extractUpdateTargetArg([]string{"--dry-run", "--target=custom:/tmp/skills"}); got != "custom:/tmp/skills" {
		t.Fatalf("extractUpdateTargetArg(equals) = %q", got)
	}
	if got := extractUpdateTargetArg([]string{"--dry-run"}); got != "codex" {
		t.Fatalf("extractUpdateTargetArg(default) = %q", got)
	}
}

func TestBuildUpdateSARIFErrorReport(t *testing.T) {
	report := updateErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     updateFatalCodeTargetReadFail,
		Message:       "failed to read update target: /tmp/skills",
		Target:        "/tmp/skills",
		Note:          "update report generation failed",
	}
	sarif := buildUpdateSARIFErrorReport(report)
	if sarif.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
	if run.Results[0].RuleID != updateFatalCodeTargetReadFail {
		t.Fatalf("rule id = %q, want %q", run.Results[0].RuleID, updateFatalCodeTargetReadFail)
	}
	if run.Results[0].Level != "error" {
		t.Fatalf("level = %q, want error", run.Results[0].Level)
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("invocation should be unsuccessful, got %+v", run.Invocations)
	}
	if run.Properties.SourceKind != "update-target" {
		t.Fatalf("source kind = %q, want update-target", run.Properties.SourceKind)
	}
}
