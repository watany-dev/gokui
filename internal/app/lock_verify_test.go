package app

import (
	"encoding/json"
	"errors"
	reportpkg "github.com/watany-dev/gokui/internal/report"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type errorStatter struct {
	err error
}

func (s errorStatter) Stat() (os.FileInfo, error) {
	return nil, s.err
}

func TestVerifyLockAndRunLockVerify(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "verify-skill")
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
	installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-skill", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	verifyReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if verifyReport.Status != "VERIFIED" {
		t.Fatalf("verify status = %q, want VERIFIED", verifyReport.Status)
	}
	assertCheckCode(t, verifyReport.Checks, "schema", lockVerifyCodeSchema)
	assertCheckCode(t, verifyReport.Checks, "name", lockVerifyCodeName)
	assertCheckCode(t, verifyReport.Checks, "lock_structure", lockVerifyCodeStructure)
	assertCheckCode(t, verifyReport.Checks, "source", lockVerifyCodeSource)
	assertCheckCode(t, verifyReport.Checks, "source_metadata", lockVerifyCodeSourceMetadata)
	assertCheckCode(t, verifyReport.Checks, "install_report", lockVerifyCodeInstallReport)
	assertCheckCode(t, verifyReport.Checks, "file_digests", lockVerifyCodeFileDigests)
	assertCheckCode(t, verifyReport.Checks, "root_hash", lockVerifyCodeRootHash)

	var stdout strings.Builder
	var stderr strings.Builder
	code := runLockVerify([]string{installedPath, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLockVerify() code = %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath, "--format", "compact"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLockVerify(compact verified) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for compact verified output, got %q", stderr.String())
	}
	compactVerified := strings.TrimSpace(stdout.String())
	if strings.Contains(compactVerified, "\n") {
		t.Fatalf("compact output should be single-line, got %q", compactVerified)
	}
	for _, marker := range []string{
		"lock_verify status=VERIFIED",
		"failed=0",
		"missing=0",
		"changed=0",
		"unexpected=0",
	} {
		if !strings.Contains(compactVerified, marker) {
			t.Fatalf("compact verified output missing %q: %q", marker, compactVerified)
		}
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath, "--format", "sarif"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLockVerify(sarif verified) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for sarif verified output, got %q", stderr.String())
	}
	var verifiedSARIF reportpkg.SARIFDocument
	if err := json.Unmarshal([]byte(stdout.String()), &verifiedSARIF); err != nil {
		t.Fatalf("sarif unmarshal (verified): %v", err)
	}
	if len(verifiedSARIF.Runs) != 1 {
		t.Fatalf("verified sarif runs = %d, want 1", len(verifiedSARIF.Runs))
	}
	if verifiedSARIF.Runs[0].Properties.Decision != "PASS" {
		t.Fatalf("verified sarif decision = %q, want PASS", verifiedSARIF.Runs[0].Properties.Decision)
	}
	if len(verifiedSARIF.Runs[0].Results) != 0 {
		t.Fatalf("verified sarif should have no results, got %d", len(verifiedSARIF.Runs[0].Results))
	}
	if !verifiedSARIF.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("verified sarif invocation should be executionSuccessful=true")
	}

	if err := os.WriteFile(filepath.Join(installedPath, "README.md"), []byte("changed"), 0o644); err != nil {
		t.Fatalf("mutate installed file: %v", err)
	}
	driftReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock(drift) error = %v", err)
	}
	if driftReport.Status != "DRIFTED" {
		t.Fatalf("drift status = %q, want DRIFTED", driftReport.Status)
	}
	if len(driftReport.Drift.ChangedFiles) == 0 {
		t.Fatalf("expected changed files, got %+v", driftReport.Drift)
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runLockVerify(drift) code = %d, want 2", code)
	}
	if !strings.Contains(stdout.String(), "status: DRIFTED") {
		t.Fatalf("stdout should include drift status, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath, "--format", "json"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runLockVerify(drift json) code = %d, want 2", code)
	}
	if !strings.Contains(stdout.String(), "\"status\": \"DRIFTED\"") {
		t.Fatalf("json output should include drift status, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath, "--format", "sarif"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runLockVerify(sarif drifted) code = %d, want 2\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for sarif drifted output, got %q", stderr.String())
	}
	var driftSARIF reportpkg.SARIFDocument
	if err := json.Unmarshal([]byte(stdout.String()), &driftSARIF); err != nil {
		t.Fatalf("sarif unmarshal (drifted): %v", err)
	}
	if len(driftSARIF.Runs) != 1 {
		t.Fatalf("drift sarif runs = %d, want 1", len(driftSARIF.Runs))
	}
	if driftSARIF.Runs[0].Properties.Decision != "DRIFTED" {
		t.Fatalf("drift sarif decision = %q, want DRIFTED", driftSARIF.Runs[0].Properties.Decision)
	}
	if len(driftSARIF.Runs[0].Results) == 0 {
		t.Fatal("drift sarif should include failed-check results")
	}
	if driftSARIF.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("drift sarif invocation should be executionSuccessful=false")
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath, "--format", "compact"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runLockVerify(compact drifted) code = %d, want 2\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for compact drifted output, got %q", stderr.String())
	}
	compactDrift := strings.TrimSpace(stdout.String())
	if strings.Contains(compactDrift, "\n") {
		t.Fatalf("compact output should be single-line, got %q", compactDrift)
	}
	for _, marker := range []string{
		"lock_verify status=DRIFTED",
		"failed=",
		"changed=",
		"path=",
	} {
		if !strings.Contains(compactDrift, marker) {
			t.Fatalf("compact drifted output missing %q: %q", marker, compactDrift)
		}
	}
}

func TestVerifyLockErrorsAndDiff(t *testing.T) {
	_, err := verifyLock(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "failed to read lockfile") {
		t.Fatalf("expected missing lockfile error, got %v", err)
	}

	if runtime.GOOS != "windows" {
		t.Run("verify root path is symlink", func(t *testing.T) {
			base := t.TempDir()
			real := filepath.Join(base, "real-skill")
			if err := os.Mkdir(real, 0o755); err != nil {
				t.Fatalf("mkdir real skill: %v", err)
			}
			if err := os.WriteFile(filepath.Join(real, installLockFile), []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
				t.Fatalf("write lockfile: %v", err)
			}
			link := filepath.Join(base, "skill-link")
			if err := os.Symlink("real-skill", link); err != nil {
				t.Fatalf("create symlink: %v", err)
			}

			_, err := verifyLock(link)
			if err == nil || !strings.Contains(err.Error(), rulepkg.LockVerifyPathSymlink.ID) {
				t.Fatalf("expected symlinked verify path rejection, got %v", err)
			}
		})
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, installLockFile), []byte("{"), 0o644); err != nil {
		t.Fatalf("write broken lock: %v", err)
	}
	_, err = verifyLock(dir)
	if err == nil || !strings.Contains(err.Error(), "invalid lockfile JSON") {
		t.Fatalf("expected invalid JSON error, got %v", err)
	}

	invalidUTF8Dir := t.TempDir()
	invalidUTF8Lock := append([]byte(`{"schema":"gokui.lock/v1","name":"skill","source":{"type":"local","input":"/tmp/skill","kind":"local-dir"},"skill":{"root_sha256":"abc"},"policy":{"profile":"strict","decision":"pass"},"note":"`), 0xff)
	invalidUTF8Lock = append(invalidUTF8Lock, []byte(`"}`)...)
	if err := os.WriteFile(filepath.Join(invalidUTF8Dir, installLockFile), invalidUTF8Lock, 0o644); err != nil {
		t.Fatalf("write invalid utf-8 lock: %v", err)
	}
	_, err = verifyLock(invalidUTF8Dir)
	if err == nil || !strings.Contains(err.Error(), rulepkg.LockfileInvalidUTF8.ID) || !strings.Contains(err.Error(), "invalid lockfile JSON") {
		t.Fatalf("expected invalid utf-8 lockfile JSON error, got %v", err)
	}

	t.Run("oversized lockfile", func(t *testing.T) {
		oversizedDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(oversizedDir, installLockFile), []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
			t.Fatalf("write oversized lockfile: %v", err)
		}
		_, err := verifyLockWithLimit(oversizedDir, 8)
		if err == nil || !strings.Contains(err.Error(), rulepkg.LockfileTooLarge.ID) || !strings.Contains(err.Error(), "failed to read lockfile") {
			t.Fatalf("expected oversized lockfile read failure, got %v", err)
		}
	})

	t.Run("lockfile path is directory", func(t *testing.T) {
		dirWithLockDir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dirWithLockDir, installLockFile), 0o755); err != nil {
			t.Fatalf("mkdir lock path dir: %v", err)
		}
		_, err := verifyLock(dirWithLockDir)
		if err == nil || !strings.Contains(err.Error(), rulepkg.LockfileSpecialFile.ID) {
			t.Fatalf("expected lockfile special-file error for directory path, got %v", err)
		}
	})

	t.Run("lockfile is unreadable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission behavior differs on windows")
		}

		dir := t.TempDir()
		lockPath := filepath.Join(dir, installLockFile)
		if err := os.WriteFile(lockPath, []byte(`{"schema":"gokui.lock/v1"}`), 0o600); err != nil {
			t.Fatalf("write lockfile: %v", err)
		}
		if err := os.Chmod(lockPath, 0o000); err != nil {
			t.Fatalf("chmod lockfile: %v", err)
		}
		defer os.Chmod(lockPath, 0o600)

		_, err := verifyLock(dir)
		if err == nil || !strings.Contains(err.Error(), "failed to read lockfile") {
			t.Fatalf("expected unreadable lockfile read error, got %v", err)
		}
	})

	missing, changed, unexpected := diffLockFiles(
		[]lockFileHash{
			{Path: "a.txt", SHA256: "1", Bytes: 1},
			{Path: "b.txt", SHA256: "2", Bytes: 2},
		},
		[]lockFileHash{
			{Path: "b.txt", SHA256: "3", Bytes: 2},
			{Path: "c.txt", SHA256: "4", Bytes: 3},
		},
	)
	if len(missing) != 1 || missing[0] != "a.txt" {
		t.Fatalf("unexpected missing: %+v", missing)
	}
	if len(changed) != 1 || changed[0] != "b.txt" {
		t.Fatalf("unexpected changed: %+v", changed)
	}
	if len(unexpected) != 1 || unexpected[0] != "c.txt" {
		t.Fatalf("unexpected unexpected files: %+v", unexpected)
	}
}

func TestLockVerifyStableFileHelpers(t *testing.T) {
	root := t.TempDir()
	firstPath := filepath.Join(root, "first.txt")
	if err := os.WriteFile(firstPath, []byte("one"), 0o644); err != nil {
		t.Fatalf("write first file: %v", err)
	}
	secondPath := filepath.Join(root, "second.txt")
	if err := os.WriteFile(secondPath, []byte("two"), 0o644); err != nil {
		t.Fatalf("write second file: %v", err)
	}

	firstInfo, err := os.Lstat(firstPath)
	if err != nil {
		t.Fatalf("lstat first file: %v", err)
	}
	if err := ensureLockfileStableFromOpen(firstInfo, errorStatter{err: errors.New("stat fail")}, firstPath); err == nil || !strings.Contains(err.Error(), "failed to read lockfile") {
		t.Fatalf("expected lockfile stat error, got %v", err)
	}
	if err := ensureInstallReportStableFromOpen(firstInfo, errorStatter{err: errors.New("stat fail")}, firstPath); err == nil || !strings.Contains(err.Error(), "failed to read install report") {
		t.Fatalf("expected install report stat error, got %v", err)
	}

	opened, err := os.Open(firstPath)
	if err != nil {
		t.Fatalf("open first file: %v", err)
	}
	defer opened.Close()
	if err := ensureLockfileStableFromOpen(firstInfo, opened, firstPath); err != nil {
		t.Fatalf("same opened lockfile should pass, got %v", err)
	}
	if err := ensureInstallReportStableFromOpen(firstInfo, opened, firstPath); err != nil {
		t.Fatalf("same opened install report should pass, got %v", err)
	}

	changed, err := os.Open(secondPath)
	if err != nil {
		t.Fatalf("open second file: %v", err)
	}
	defer changed.Close()
	err = ensureLockfileStableFromOpen(firstInfo, changed, secondPath)
	if err == nil || !strings.Contains(err.Error(), rulepkg.LockfileSourceChangedDuringRead.ID) || !strings.Contains(err.Error(), "failed to read lockfile") {
		t.Fatalf("expected lockfile source-changed read error, got %v", err)
	}
	err = ensureInstallReportStableFromOpen(firstInfo, changed, secondPath)
	if err == nil || !strings.Contains(err.Error(), rulepkg.InstallReportSourceChangedDuringRead.ID) {
		t.Fatalf("expected install-report source-changed error, got %v", err)
	}
}

func TestLockVerifyHelpers(t *testing.T) {
	if !isCanonicalSHA256Hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Fatal("expected canonical digest to pass")
	}
	if isCanonicalSHA256Hex("x") {
		t.Fatal("invalid digest should fail canonical check")
	}
	if isCanonicalSHA256Hex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") {
		t.Fatal("uppercase digest should fail canonical check")
	}
	if isCanonicalSHA256Hex(" 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ") {
		t.Fatal("surrounding whitespace should fail canonical check")
	}

	validPaths := []string{"SKILL.md", "references/readme.md", ".gokui-report.json"}
	for _, p := range validPaths {
		if !isValidLockRelativePath(p) {
			t.Fatalf("expected valid path: %s", p)
		}
	}
	invalidPaths := []string{"", ".", "..", "../x", "/x", `..\x`, `a\b`, "C:/x", "c:/x", "D:relative/path", "z:tmp", "SKILL.md\nx", "SKILL.md\tx", "SKILL.md\x7fx", "SKILL.md\u0085x", "SKILL.md\u200dx", " SKILL.md", "SKILL.md ", string([]byte{'b', 'a', 'd', 0xff})}
	for _, p := range invalidPaths {
		if isValidLockRelativePath(p) {
			t.Fatalf("expected invalid path: %s", p)
		}
	}
}

func assertCheckOK(t *testing.T, checks []lockVerifyCheck, name string) {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			if !c.OK {
				t.Fatalf("check %s should pass: %+v", name, c)
			}
			return
		}
	}
	t.Fatalf("check %s not found", name)
}

func assertCheckFailedContains(t *testing.T, checks []lockVerifyCheck, name string, contains string) {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			if c.OK {
				t.Fatalf("check %s should fail: %+v", name, c)
			}
			if !strings.Contains(c.Detail, contains) {
				t.Fatalf("check %s detail = %q, want contains %q", name, c.Detail, contains)
			}
			return
		}
	}
	t.Fatalf("check %s not found", name)
}

func assertCheckCode(t *testing.T, checks []lockVerifyCheck, name string, code string) {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			if c.Code != code {
				t.Fatalf("check %s code = %q, want %q", name, c.Code, code)
			}
			return
		}
	}
	t.Fatalf("check %s not found", name)
}
