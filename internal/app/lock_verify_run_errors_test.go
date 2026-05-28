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

func TestRunLockVerifyErrorPathsAndDriftKinds(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := runLockVerify([]string{"--format"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(parse error) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "missing value for --format") {
		t.Fatalf("stderr should include parse error, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{"--bad", "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(parse json error) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json parse error output, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
		t.Fatalf("stdout should include error status, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeArgsInvalid+"\"") {
		t.Fatalf("stdout should include args-invalid error_code, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"skill_path\": \".\"") {
		t.Fatalf("stdout should include default skill_path for parse error, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{"--bad", "--format", "sarif"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(parse sarif error) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for sarif parse error output, got %q", stderr.String())
	}
	var parseSARIF reportpkg.SARIFDocument
	if err := json.Unmarshal([]byte(stdout.String()), &parseSARIF); err != nil {
		t.Fatalf("sarif parse (parse error): %v", err)
	}
	if len(parseSARIF.Runs) != 1 || len(parseSARIF.Runs[0].Results) != 1 {
		t.Fatalf("unexpected sarif parse-error structure: %+v", parseSARIF)
	}
	if parseSARIF.Runs[0].Results[0].RuleID != lockVerifyErrorCodeArgsInvalid {
		t.Fatalf("parse sarif rule id = %q, want %q", parseSARIF.Runs[0].Results[0].RuleID, lockVerifyErrorCodeArgsInvalid)
	}
	if parseSARIF.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("parse sarif invocation should be executionSuccessful=false")
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{filepath.Join(t.TempDir(), "missing-skill")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(missing lock) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "failed to read lockfile") {
		t.Fatalf("stderr should include missing lockfile error, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{filepath.Join(t.TempDir(), "missing-skill-compact"), "--format", "compact"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(missing lock compact) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty for compact error output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "failed to read lockfile") {
		t.Fatalf("stderr should include missing lockfile error for compact output, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{filepath.Join(t.TempDir(), "missing-skill-json"), "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(missing lock json) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
		t.Fatalf("stdout should include error status, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeReadLockfile+"\"") {
		t.Fatalf("stdout should include read-lockfile error code, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "\"rule_id\":") {
		t.Fatalf("stdout should omit rule_id when no rule-prefixed error is present, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{filepath.Join(t.TempDir(), "missing-skill-sarif"), "--format", "sarif"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(missing lock sarif) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for sarif error output, got %q", stderr.String())
	}
	var readSARIF reportpkg.SARIFDocument
	if err := json.Unmarshal([]byte(stdout.String()), &readSARIF); err != nil {
		t.Fatalf("sarif parse (read error): %v", err)
	}
	if len(readSARIF.Runs) != 1 || len(readSARIF.Runs[0].Results) != 1 {
		t.Fatalf("unexpected sarif read-error structure: %+v", readSARIF)
	}
	if readSARIF.Runs[0].Results[0].RuleID != lockVerifyErrorCodeReadLockfile {
		t.Fatalf("read sarif rule id = %q, want %q", readSARIF.Runs[0].Results[0].RuleID, lockVerifyErrorCodeReadLockfile)
	}
	if readSARIF.Runs[0].Properties.Decision != "ERROR" {
		t.Fatalf("read sarif decision = %q, want ERROR", readSARIF.Runs[0].Properties.Decision)
	}
	if !strings.Contains(readSARIF.Runs[0].Properties.Note, "error_code="+lockVerifyErrorCodeReadLockfile) {
		t.Fatalf("read sarif note should include error_code, got %q", readSARIF.Runs[0].Properties.Note)
	}

	if runtime.GOOS != "windows" {
		stdout.Reset()
		stderr.Reset()
		symlinkPathBase := t.TempDir()
		symlinkPathReal := filepath.Join(symlinkPathBase, "real-skill")
		if err := os.Mkdir(symlinkPathReal, 0o755); err != nil {
			t.Fatalf("mkdir real lock-verify path: %v", err)
		}
		if err := os.WriteFile(filepath.Join(symlinkPathReal, installLockFile), []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
			t.Fatalf("write lock in real path: %v", err)
		}
		symlinkPath := filepath.Join(symlinkPathBase, "skill-link")
		if err := os.Symlink("real-skill", symlinkPath); err != nil {
			t.Fatalf("create lock-verify path symlink: %v", err)
		}

		code = runLockVerify([]string{symlinkPath}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runLockVerify(path symlink human) code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty for human error output, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), rulepkg.LockVerifyPathSymlink.ID) {
			t.Fatalf("stderr should include lock-verify path symlink rule, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runLockVerify([]string{symlinkPath, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runLockVerify(path symlink json) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
			t.Fatalf("stdout should include error status, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+rulepkg.LockVerifyPathSymlink.ID+"\"") {
			t.Fatalf("stdout should include lock-verify path symlink rule_id, got %q", stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		symlinkDir := t.TempDir()
		realLock := filepath.Join(symlinkDir, "real.lock")
		if err := os.WriteFile(realLock, []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
			t.Fatalf("write real lock: %v", err)
		}
		if err := os.Symlink("real.lock", filepath.Join(symlinkDir, installLockFile)); err != nil {
			t.Fatalf("create lock symlink: %v", err)
		}
		code = runLockVerify([]string{symlinkDir, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runLockVerify(lockfile symlink json) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeReadLockfile+"\"") {
			t.Fatalf("stdout should include read-lockfile error code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+rulepkg.LockfileSymlink.ID+"\"") {
			t.Fatalf("stdout should include lockfile symlink rule_id, got %q", stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	origLimit := maxLockVerifyLockFileBytes
	maxLockVerifyLockFileBytes = 8
	oversizedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(oversizedDir, installLockFile), []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
		t.Fatalf("write oversized lockfile: %v", err)
	}
	code = runLockVerify([]string{oversizedDir, "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(oversized lock json) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeReadLockfile+"\"") {
		t.Fatalf("stdout should include read-lockfile error code, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"rule_id\": \""+rulepkg.LockfileTooLarge.ID+"\"") {
		t.Fatalf("stdout should include lockfile-too-large rule_id, got %q", stdout.String())
	}
	maxLockVerifyLockFileBytes = origLimit

	stdout.Reset()
	stderr.Reset()
	lockDirSkill := t.TempDir()
	if err := os.Mkdir(filepath.Join(lockDirSkill, installLockFile), 0o755); err != nil {
		t.Fatalf("mkdir lockfile directory path: %v", err)
	}
	code = runLockVerify([]string{lockDirSkill, "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(lockfile special-file json) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeReadLockfile+"\"") {
		t.Fatalf("stdout should include read-lockfile error code, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"rule_id\": \""+rulepkg.LockfileSpecialFile.ID+"\"") {
		t.Fatalf("stdout should include lockfile special-file rule_id, got %q", stdout.String())
	}

	if runtime.GOOS != "windows" {
		stdout.Reset()
		stderr.Reset()
		src := createSkillSourceForInstallTest(t, "digest-symlink-skill")
		targetRoot := filepath.Join(t.TempDir(), "skills-digest-symlink")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source:        source{Input: src, Kind: "local-dir"},
			PolicyProfile: "strict",
			Decision:      "PASS",
		}
		installedPath, _, err := installSkillAtomic(src, targetRoot, "digest-symlink-skill", report)
		if err != nil {
			t.Fatalf("installSkillAtomic() error = %v", err)
		}
		if err := os.Symlink("README.md", filepath.Join(installedPath, "link.txt")); err != nil {
			t.Fatalf("create symlink in installed skill: %v", err)
		}
		code = runLockVerify([]string{installedPath, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runLockVerify(digest symlink json) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeDigestFailed+"\"") {
			t.Fatalf("stdout should include digest-failed error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+rulepkg.InstallDigestSymlink.ID+"\"") {
			t.Fatalf("stdout should include digest symlink rule_id, got %q", stdout.String())
		}
	}

	src := createSkillSourceForInstallTest(t, "drift-kinds-skill")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "drift-kinds-skill", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}
	if err := os.Remove(filepath.Join(installedPath, "README.md")); err != nil {
		t.Fatalf("remove README for missing drift: %v", err)
	}
	if err := os.WriteFile(filepath.Join(installedPath, "extra.txt"), []byte("extra"), 0o644); err != nil {
		t.Fatalf("write extra drift file: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runLockVerify(drift kinds) code = %d, want 2", code)
	}
	if !strings.Contains(stdout.String(), "missing: README.md") {
		t.Fatalf("stdout should include missing files, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "unexpected: extra.txt") {
		t.Fatalf("stdout should include unexpected files, got %q", stdout.String())
	}
}
