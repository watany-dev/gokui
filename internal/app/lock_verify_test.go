package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/quick"
)

func TestParseLockVerifyArgs(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		got, err := parseLockVerifyArgs(nil)
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "." || got.Format != "human" {
			t.Fatalf("unexpected defaults: %+v", got)
		}
	})

	t.Run("path and json format", func(t *testing.T) {
		got, err := parseLockVerifyArgs([]string{"./skill", "--format", "json"})
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "./skill" || got.Format != "json" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})

	t.Run("errors", func(t *testing.T) {
		_, err := parseLockVerifyArgs([]string{"--format"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --format") {
			t.Fatalf("expected format value error, got %v", err)
		}
		_, err = parseLockVerifyArgs([]string{"./a", "./b"})
		if err == nil || !strings.Contains(err.Error(), "at most one path") {
			t.Fatalf("expected too many paths error, got %v", err)
		}
		_, err = parseLockVerifyArgs([]string{"--bad"})
		if err == nil || !strings.Contains(err.Error(), "unknown lock verify option") {
			t.Fatalf("expected unknown option error, got %v", err)
		}
		_, err = parseLockVerifyArgs([]string{"--format", "xml"})
		if err == nil || !strings.Contains(err.Error(), "unsupported lock verify format") {
			t.Fatalf("expected unsupported format error, got %v", err)
		}
	})

	t.Run("json-request and path extraction helpers", func(t *testing.T) {
		if !lockVerifyArgsRequestJSON([]string{"--format", "json"}) {
			t.Fatal("lockVerifyArgsRequestJSON() should detect --format json")
		}
		if !lockVerifyArgsRequestJSON([]string{"--format=json"}) {
			t.Fatal("lockVerifyArgsRequestJSON() should detect --format=json")
		}
		if lockVerifyArgsRequestJSON([]string{"--format", "human"}) {
			t.Fatal("lockVerifyArgsRequestJSON() should be false for human format")
		}

		if got := extractLockVerifyPathArg([]string{"./skill", "--format", "json"}); got != "./skill" {
			t.Fatalf("extractLockVerifyPathArg() = %q, want ./skill", got)
		}
		if got := extractLockVerifyPathArg([]string{"--format=json", "./skill"}); got != "./skill" {
			t.Fatalf("extractLockVerifyPathArg(equals) = %q, want ./skill", got)
		}
		if got := extractLockVerifyPathArg([]string{"--bad", "--format", "json"}); got != "." {
			t.Fatalf("extractLockVerifyPathArg(default) = %q, want .", got)
		}
	})
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
			if err == nil || !strings.Contains(err.Error(), ruleLockVerifyPathSymlink) {
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

	t.Run("oversized lockfile", func(t *testing.T) {
		origLimit := maxLockVerifyLockFileBytes
		maxLockVerifyLockFileBytes = 8
		t.Cleanup(func() { maxLockVerifyLockFileBytes = origLimit })

		oversizedDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(oversizedDir, installLockFile), []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
			t.Fatalf("write oversized lockfile: %v", err)
		}
		_, err := verifyLock(oversizedDir)
		if err == nil || !strings.Contains(err.Error(), ruleLockfileTooLarge) || !strings.Contains(err.Error(), "failed to read lockfile") {
			t.Fatalf("expected oversized lockfile read failure, got %v", err)
		}
	})

	t.Run("lockfile path is directory", func(t *testing.T) {
		dirWithLockDir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dirWithLockDir, installLockFile), 0o755); err != nil {
			t.Fatalf("mkdir lock path dir: %v", err)
		}
		_, err := verifyLock(dirWithLockDir)
		if err == nil || !strings.Contains(err.Error(), ruleLockfileSpecialFile) {
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
	code = runLockVerify([]string{filepath.Join(t.TempDir(), "missing-skill")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(missing lock) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "failed to read lockfile") {
		t.Fatalf("stderr should include missing lockfile error, got %q", stderr.String())
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
		if !strings.Contains(stderr.String(), ruleLockVerifyPathSymlink) {
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
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleLockVerifyPathSymlink+"\"") {
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
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleLockfileSymlink+"\"") {
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
	if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleLockfileTooLarge+"\"") {
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
	if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleLockfileSpecialFile+"\"") {
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
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleInstallDigestSymlink+"\"") {
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

func TestClassifyLockVerifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "wrapped lockfile read failure",
			err:  fmt.Errorf("wrap: %w", errLockfileReadFailed),
			want: lockVerifyErrorCodeReadLockfile,
		},
		{
			name: "wrapped invalid lockfile json",
			err:  fmt.Errorf("wrap: %w", errLockfileInvalidJSON),
			want: lockVerifyErrorCodeInvalidLockfile,
		},
		{
			name: "wrapped digest failure",
			err:  fmt.Errorf("wrap: %w", errDigestBuildFailed),
			want: lockVerifyErrorCodeDigestFailed,
		},
		{
			name: "text-only lockfile phrase does not match",
			err:  errors.New("failed to read lockfile: /x/gokui.lock"),
			want: lockVerifyErrorCodeUnknown,
		},
		{
			name: "other error remains unknown",
			err:  errors.New("other"),
			want: lockVerifyErrorCodeUnknown,
		},
	}
	for _, tc := range cases {
		got := classifyLockVerifyError(tc.err)
		if got != tc.want {
			t.Fatalf("%s: classifyLockVerifyError(%v) = %q, want %q", tc.name, tc.err, got, tc.want)
		}
	}
}

func TestVerifyLockSourceChecks(t *testing.T) {
	lock := installLock{
		Schema: "gokui.lock/v1",
		Source: lockSource{
			Type:  "local",
			Input: "/tmp/skill",
			Kind:  "local-dir",
		},
	}
	ok, detail := verifyLockSource(lock)
	if !ok {
		t.Fatalf("expected source check pass, detail=%q", detail)
	}

	lock.Source.Kind = ""
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("empty kind should fail")
	}

	lock.Source.Kind = "local-dir"
	lock.Source.Input = ""
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("empty input should fail")
	}

	lock.Source.Input = "/tmp/skill"
	lock.Source.Kind = "unsupported"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("unsupported kind should fail")
	}

	lock.Source.Kind = "local-dir"
	lock.Source.Type = "archive"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type/kind mismatch should fail")
	}

	lock.Source.Kind = "github-source"
	lock.Source.Type = "github"
	lock.Source.Input = "github:org/repo/path@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("invalid github source syntax should fail")
	}

	lock.Source.Input = "github:org/repo//skills/demo@main"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("floating github ref should fail")
	}

	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, detail := verifyLockSource(lock); !ok {
		t.Fatalf("expected github pinned source check pass, detail=%q", detail)
	}
}

func TestVerifyLockSourceMetadataCheck(t *testing.T) {
	t.Run("local sources do not require source metadata", func(t *testing.T) {
		lock := installLock{
			Schema: "gokui.lock/v1",
			Source: lockSource{
				Type:  "local",
				Input: "/tmp/skill",
				Kind:  "local-dir",
			},
		}
		ok, detail := verifyLockSourceMetadata(t.TempDir(), lock)
		if !ok {
			t.Fatalf("expected source metadata check pass for local source: %q", detail)
		}
		if !strings.Contains(detail, "not required") {
			t.Fatalf("unexpected detail: %q", detail)
		}
	})

	t.Run("github sources require source metadata", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "verify-source-meta")
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
		installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-source-meta", report)
		if err != nil {
			t.Fatalf("installSkillAtomic() error = %v", err)
		}

		lockPath := filepath.Join(installedPath, installLockFile)
		raw, err := os.ReadFile(lockPath)
		if err != nil {
			t.Fatalf("read lock: %v", err)
		}
		var lock installLock
		if err := json.Unmarshal(raw, &lock); err != nil {
			t.Fatalf("unmarshal lock: %v", err)
		}
		lock.Source = lockSource{
			Type:  "github",
			Input: "github:org/repo//skills/verify-source-meta@abc1234a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		}
		updated, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(lockPath, updated, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		ok, detail := verifyLockSourceMetadata(installedPath, lock)
		if ok {
			t.Fatalf("expected source metadata failure without metadata file: %q", detail)
		}
		if !strings.Contains(detail, "missing source metadata") {
			t.Fatalf("expected missing metadata detail, got %q", detail)
		}

		_, installedRootHash, err := buildFileDigestsFiltered(installedPath, map[string]struct{}{
			sourceMetadataFile: {},
			installReportFile:  {},
			installLockFile:    {},
		})
		if err != nil {
			t.Fatalf("buildFileDigestsFiltered() error = %v", err)
		}
		if err := writeSourceMetadata(installedPath, sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     "github:org/repo//skills/verify-source-meta@abc1234a4b5c6d7e8f901234567890abcdef1234",
			SourceKind:      "github-source",
			ResolvedRef:     "abc1234a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: installedRootHash,
		}); err != nil {
			t.Fatalf("writeSourceMetadata() error = %v", err)
		}

		ok, detail = verifyLockSourceMetadata(installedPath, lock)
		if !ok {
			t.Fatalf("expected source metadata pass, detail=%q", detail)
		}
		if !strings.Contains(detail, "metadata matches") {
			t.Fatalf("unexpected pass detail: %q", detail)
		}
	})
}

func TestVerifyLockDetectsSourceDrift(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "source-drift-skill")
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
	installedPath, _, err := installSkillAtomic(src, targetRoot, "source-drift-skill", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lockPath := filepath.Join(installedPath, installLockFile)
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read lock: %v", err)
	}
	var lock installLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatalf("unmarshal lock: %v", err)
	}
	lock.Source.Type = "archive"
	updated, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal updated lock: %v", err)
	}
	if err := os.WriteFile(lockPath, updated, 0o644); err != nil {
		t.Fatalf("write updated lock: %v", err)
	}

	reportOut, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if reportOut.Status != "DRIFTED" {
		t.Fatalf("status = %q, want DRIFTED", reportOut.Status)
	}

	var foundSourceCheck bool
	for _, c := range reportOut.Checks {
		if c.Name == "source" {
			foundSourceCheck = true
			if c.OK {
				t.Fatalf("source check should fail: %+v", c)
			}
		}
	}
	if !foundSourceCheck {
		t.Fatal("source check should exist")
	}
}

func TestVerifyLockStructureAndReportChecks(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "structure-report-skill")
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
	installedPath, _, err := installSkillAtomic(src, targetRoot, "structure-report-skill", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	base, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if base.Status != "VERIFIED" {
		t.Fatalf("status = %q, want VERIFIED", base.Status)
	}
	assertCheckOK(t, base.Checks, "lock_structure")
	assertCheckOK(t, base.Checks, "install_report")

	t.Run("invalid lock structure", func(t *testing.T) {
		lockPath := filepath.Join(installedPath, installLockFile)
		raw, err := os.ReadFile(lockPath)
		if err != nil {
			t.Fatalf("read lock: %v", err)
		}
		var lock installLock
		if err := json.Unmarshal(raw, &lock); err != nil {
			t.Fatalf("unmarshal lock: %v", err)
		}
		lock.Skill.Files = append(lock.Skill.Files, lockFileHash{
			Path:   lock.Skill.Files[0].Path,
			SHA256: lock.Skill.Files[0].SHA256,
			Bytes:  lock.Skill.Files[0].Bytes,
		})
		updated, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(lockPath, updated, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		out, err := verifyLock(installedPath)
		if err != nil {
			t.Fatalf("verifyLock() error = %v", err)
		}
		if out.Status != "DRIFTED" {
			t.Fatalf("status = %q, want DRIFTED", out.Status)
		}
		assertCheckFailedContains(t, out.Checks, "lock_structure", "duplicate lock file path")
	})
}

func TestVerifyInstallReportFailures(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "report-failure-skill")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	seedReport := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "report-failure-skill", seedReport)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lock, err := readInstallLock(filepath.Join(installedPath, installLockFile))
	if err != nil {
		t.Fatalf("readInstallLock() error = %v", err)
	}

	t.Run("missing report", func(t *testing.T) {
		reportPath := filepath.Join(installedPath, installReportFile)
		originalReport, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("read original report: %v", err)
		}
		if err := os.Remove(reportPath); err != nil {
			t.Fatalf("remove report: %v", err)
		}
		ok, detail := verifyInstallReport(installedPath, lock)
		if ok || !strings.Contains(detail, "failed to read install report") {
			t.Fatalf("expected missing report failure, got ok=%v detail=%q", ok, detail)
		}
		if err := os.WriteFile(reportPath, originalReport, 0o644); err != nil {
			t.Fatalf("restore report: %v", err)
		}
	})

	t.Run("source mismatch", func(t *testing.T) {
		reportPath := filepath.Join(installedPath, installReportFile)
		raw, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("read report: %v", err)
		}
		var rep installReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatalf("unmarshal report: %v", err)
		}
		rep.Source.Input = "github:org/repo//skills/report-failure-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
		updated, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(reportPath, updated, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}

		ok, detail := verifyInstallReport(installedPath, lock)
		if ok || !strings.Contains(detail, "source does not match lock source") {
			t.Fatalf("expected source mismatch failure, got ok=%v detail=%q", ok, detail)
		}
	})
}

func TestVerifyInstallReportValidationBranches(t *testing.T) {
	skillPath := t.TempDir()
	lock := installLock{
		Source: lockSource{
			Type:  "local",
			Input: "/tmp/src",
			Kind:  "local-dir",
		},
		Policy: lockPolicy{
			Profile:  "strict",
			Decision: "pass",
		},
	}

	writeReport := func(t *testing.T, payload string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(skillPath, installReportFile), []byte(payload), 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}

	t.Run("invalid json", func(t *testing.T) {
		writeReport(t, "{")
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, "invalid install report JSON") {
			t.Fatalf("expected invalid json failure, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("oversized report", func(t *testing.T) {
		origLimit := maxInstallReportFileBytes
		maxInstallReportFileBytes = 8
		t.Cleanup(func() { maxInstallReportFileBytes = origLimit })
		writeReport(t, `{"schema_version":"0.1.0-draft"}`)
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, ruleInstallReportTooLarge) {
			t.Fatalf("expected oversized report failure, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("report path is directory", func(t *testing.T) {
		reportPath := filepath.Join(skillPath, installReportFile)
		if err := os.Remove(reportPath); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove report file: %v", err)
		}
		if err := os.Mkdir(reportPath, 0o755); err != nil {
			t.Fatalf("mkdir report path: %v", err)
		}
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, ruleInstallReportSpecialFile) {
			t.Fatalf("expected special-file failure for directory report path, got ok=%v detail=%q", ok, detail)
		}
		if err := os.Remove(reportPath); err != nil {
			t.Fatalf("remove report directory: %v", err)
		}
	})

	t.Run("report path is symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}
		reportPath := filepath.Join(skillPath, installReportFile)
		if err := os.Remove(reportPath); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove report file: %v", err)
		}
		target := filepath.Join(skillPath, "real-report.json")
		if err := os.WriteFile(target, []byte(`{"schema_version":"0.1.0-draft"}`), 0o644); err != nil {
			t.Fatalf("write real report: %v", err)
		}
		if err := os.Symlink("real-report.json", reportPath); err != nil {
			t.Fatalf("create report symlink: %v", err)
		}
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, ruleInstallReportSymlink) {
			t.Fatalf("expected report symlink rejection, got ok=%v detail=%q", ok, detail)
		}
		if err := os.Remove(reportPath); err != nil {
			t.Fatalf("remove report symlink: %v", err)
		}
	})

	t.Run("report path under ancestor symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		base := t.TempDir()
		realParent := filepath.Join(base, "real-parent")
		if err := os.Mkdir(realParent, 0o755); err != nil {
			t.Fatalf("mkdir real parent: %v", err)
		}
		realSkill := filepath.Join(realParent, "skill")
		if err := os.Mkdir(realSkill, 0o755); err != nil {
			t.Fatalf("mkdir real skill: %v", err)
		}
		valid := installReport{
			SchemaVersion: "0.1.0-draft",
			Source: source{
				Input: "/tmp/src",
				Kind:  "local-dir",
			},
			PolicyProfile: "strict",
			Decision:      "PASS",
			InstalledPath: filepath.Join(base, "link-parent", "skill"),
			Installed:     true,
		}
		raw, err := json.MarshalIndent(valid, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(filepath.Join(realSkill, installReportFile), raw, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
		linkParent := filepath.Join(base, "link-parent")
		if err := os.Symlink("real-parent", linkParent); err != nil {
			t.Fatalf("create parent symlink: %v", err)
		}

		ok, detail := verifyInstallReport(filepath.Join(linkParent, "skill"), lock)
		if ok || !strings.Contains(detail, ruleInstallReportSymlink) {
			t.Fatalf("expected ancestor report symlink rejection, got ok=%v detail=%q", ok, detail)
		}
	})

	valid := installReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: "/tmp/src",
			Kind:  "local-dir",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
		InstalledPath: skillPath,
		Installed:     true,
	}
	raw, err := json.MarshalIndent(valid, "", "  ")
	if err != nil {
		t.Fatalf("marshal valid report: %v", err)
	}
	writeReport(t, string(raw))
	if ok, _ := verifyInstallReport(skillPath, lock); !ok {
		t.Fatal("expected valid report check pass")
	}

	cases := []struct {
		name      string
		mutate    func(*installReport)
		detailHas string
	}{
		{
			name: "empty schema",
			mutate: func(r *installReport) {
				r.SchemaVersion = ""
			},
			detailHas: "schema_version is empty",
		},
		{
			name: "empty profile",
			mutate: func(r *installReport) {
				r.PolicyProfile = ""
			},
			detailHas: "policy profile is empty",
		},
		{
			name: "profile mismatch",
			mutate: func(r *installReport) {
				r.PolicyProfile = "team"
			},
			detailHas: "policy profile does not match",
		},
		{
			name: "decision mismatch",
			mutate: func(r *installReport) {
				r.Decision = "REJECTED"
			},
			detailHas: "decision does not match",
		},
		{
			name: "installed false",
			mutate: func(r *installReport) {
				r.Installed = false
			},
			detailHas: "installed must be true",
		},
		{
			name: "path mismatch",
			mutate: func(r *installReport) {
				r.InstalledPath = filepath.Join(skillPath, "other")
			},
			detailHas: "path mismatch",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := valid
			tc.mutate(&rep)
			mutRaw, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				t.Fatalf("marshal report: %v", err)
			}
			writeReport(t, string(mutRaw))

			ok, detail := verifyInstallReport(skillPath, lock)
			if ok || !strings.Contains(detail, tc.detailHas) {
				t.Fatalf("expected detail containing %q, got ok=%v detail=%q", tc.detailHas, ok, detail)
			}
		})
	}
}

func TestVerifyLockStructureValidationBranches(t *testing.T) {
	valid := installLock{
		Schema:      "gokui.lock/v1",
		Name:        "x",
		InstalledAt: "2026-05-23T00:00:00Z",
		Source: lockSource{
			Type:  "local",
			Input: "/tmp/x",
			Kind:  "local-dir",
		},
		Skill: lockSkill{
			RootSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Files: []lockFileHash{
				{
					Path:   "SKILL.md",
					SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					Bytes:  10,
				},
			},
		},
		Policy: lockPolicy{
			Profile:  "strict",
			Decision: "pass",
		},
	}

	if ok, _ := verifyLockStructure(valid); !ok {
		t.Fatal("expected valid lock structure")
	}

	cases := []struct {
		name     string
		mutate   func(*installLock)
		detailIn string
	}{
		{
			name: "empty installed_at",
			mutate: func(l *installLock) {
				l.InstalledAt = ""
			},
			detailIn: "installed_at is empty",
		},
		{
			name: "invalid installed_at",
			mutate: func(l *installLock) {
				l.InstalledAt = "x"
			},
			detailIn: "must be RFC3339",
		},
		{
			name: "empty profile",
			mutate: func(l *installLock) {
				l.Policy.Profile = ""
			},
			detailIn: "policy profile is empty",
		},
		{
			name: "invalid decision",
			mutate: func(l *installLock) {
				l.Policy.Decision = "warn"
			},
			detailIn: "lock policy decision must be pass",
		},
		{
			name: "rejected decision",
			mutate: func(l *installLock) {
				l.Policy.Decision = "rejected"
			},
			detailIn: "lock policy decision must be pass",
		},
		{
			name: "invalid root hash",
			mutate: func(l *installLock) {
				l.Skill.RootSHA256 = "x"
			},
			detailIn: "root_sha256 must be a 64-char hex digest",
		},
		{
			name: "empty files",
			mutate: func(l *installLock) {
				l.Skill.Files = nil
			},
			detailIn: "files is empty",
		},
		{
			name: "invalid file path",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "../x"
			},
			detailIn: "file path is invalid",
		},
		{
			name: "duplicate file path",
			mutate: func(l *installLock) {
				l.Skill.Files = append(l.Skill.Files, l.Skill.Files[0])
			},
			detailIn: "duplicate lock file path",
		},
		{
			name: "invalid file hash",
			mutate: func(l *installLock) {
				l.Skill.Files[0].SHA256 = "x"
			},
			detailIn: "file sha256 is invalid",
		},
		{
			name: "negative bytes",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Bytes = -1
			},
			detailIn: "bytes is negative",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := valid
			l.Skill.Files = append([]lockFileHash(nil), valid.Skill.Files...)
			tc.mutate(&l)
			ok, detail := verifyLockStructure(l)
			if ok || !strings.Contains(detail, tc.detailIn) {
				t.Fatalf("expected failure containing %q, got ok=%v detail=%q", tc.detailIn, ok, detail)
			}
		})
	}
}

func TestLockVerifyHelpers(t *testing.T) {
	if !isSHA256Hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Fatal("expected valid hex digest")
	}
	if isSHA256Hex("x") {
		t.Fatal("invalid digest should fail")
	}

	validPaths := []string{"SKILL.md", "references/readme.md", ".gokui-report.json"}
	for _, p := range validPaths {
		if !isValidLockRelativePath(p) {
			t.Fatalf("expected valid path: %s", p)
		}
	}
	invalidPaths := []string{"", ".", "..", "../x", "/x", `..\x`, `a\b`, "C:/x", "c:/x", "D:relative/path", "z:tmp"}
	for _, p := range invalidPaths {
		if isValidLockRelativePath(p) {
			t.Fatalf("expected invalid path: %s", p)
		}
	}
}

func TestLockRelativePathProperties(t *testing.T) {
	t.Run("windows drive prefixes are always invalid", func(t *testing.T) {
		prop := func(letter uint8, tail string) bool {
			drive := byte('A' + (letter % 26))
			path := fmt.Sprintf("%c:%s", drive, tail)
			return !isValidLockRelativePath(path)
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("drive-prefix property failed: %v", err)
		}
	})

	t.Run("paths with backslash are always invalid", func(t *testing.T) {
		prop := func(a string, b string) bool {
			path := a + `\` + b
			return !isValidLockRelativePath(path)
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("backslash property failed: %v", err)
		}
	})
}

func TestVerifyInstallReportDecisionAndFindingsInvariant(t *testing.T) {
	skillPath := t.TempDir()
	lock := installLock{
		Source: lockSource{
			Type:  "local",
			Input: "/tmp/src",
			Kind:  "local-dir",
		},
		Policy: lockPolicy{
			Profile:  "strict",
			Decision: "pass",
		},
		Findings: lockFindingSummary{
			Critical: 0,
			High:     1,
			Medium:   0,
			Low:      0,
		},
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: "/tmp/src",
			Kind:  "local-dir",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
		InstalledPath: skillPath,
		Installed:     true,
		Findings: []inspectFinding{
			{ID: "UNPINNED_RUNTIME_TOOL", Severity: "high", File: "SKILL.md", Line: 1, Summary: "x"},
		},
	}

	writeReport := func(t *testing.T, in installReport) {
		t.Helper()
		raw, err := json.MarshalIndent(in, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(filepath.Join(skillPath, installReportFile), raw, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}

	writeReport(t, report)
	if ok, _ := verifyInstallReport(skillPath, lock); !ok {
		t.Fatal("expected baseline install report check pass")
	}

	t.Run("decision must be pass", func(t *testing.T) {
		mutLock := lock
		mutLock.Policy.Decision = "rejected"

		mutReport := report
		mutReport.Decision = "REJECTED"
		writeReport(t, mutReport)

		ok, detail := verifyInstallReport(skillPath, mutLock)
		if ok || !strings.Contains(detail, "decision must be pass") {
			t.Fatalf("expected pass-only decision failure, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("findings summary mismatch", func(t *testing.T) {
		mutReport := report
		mutReport.Findings = nil
		writeReport(t, mutReport)

		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, "findings summary does not match lock findings") {
			t.Fatalf("expected findings mismatch failure, got ok=%v detail=%q", ok, detail)
		}
	})
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
