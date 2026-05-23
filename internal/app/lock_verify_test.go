package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, installLockFile), []byte("{"), 0o644); err != nil {
		t.Fatalf("write broken lock: %v", err)
	}
	_, err = verifyLock(dir)
	if err == nil || !strings.Contains(err.Error(), "invalid lockfile JSON") {
		t.Fatalf("expected invalid JSON error, got %v", err)
	}

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
	code = runLockVerify([]string{filepath.Join(t.TempDir(), "missing-skill")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(missing lock) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "failed to read lockfile") {
		t.Fatalf("stderr should include missing lockfile error, got %q", stderr.String())
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
	lock.Source.Input = "github:org/repo/path@abc1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("invalid github source syntax should fail")
	}

	lock.Source.Input = "github:org/repo//skills/demo@main"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("floating github ref should fail")
	}

	lock.Source.Input = "github:org/repo//skills/demo@abc1234"
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
			Input: "github:org/repo//skills/verify-source-meta@abc1234",
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
			SourceInput:     "github:org/repo//skills/verify-source-meta@abc1234",
			SourceKind:      "github-source",
			ResolvedRef:     "abc1234",
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
