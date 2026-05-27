package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallSkillAtomicWritesMetadata(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "clean-skill")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}

	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: src,
			Kind:  "local-dir",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
		Findings: []inspectFinding{
			{ID: "LOW_EXAMPLE", Severity: "low", File: "SKILL.md", Line: 1, Summary: "example"},
		},
		Installed: false,
		Note:      "test",
	}

	installedPath, result, err := installSkillAtomic(src, targetRoot, "clean-skill", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}
	if result != installResultInstalled {
		t.Fatalf("install result = %q, want %q", result, installResultInstalled)
	}
	if installedPath != filepath.Join(targetRoot, "clean-skill") {
		t.Fatalf("installed path = %q", installedPath)
	}

	reportPath := filepath.Join(installedPath, installReportFile)
	lockPath := filepath.Join(installedPath, installLockFile)
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("expected report file: %v", err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("expected lock file: %v", err)
	}

	var lock installLock
	rawLock, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read lock: %v", err)
	}
	if err := json.Unmarshal(rawLock, &lock); err != nil {
		t.Fatalf("unmarshal lock: %v", err)
	}
	if lock.Schema != "gokui.lock/v1" {
		t.Fatalf("lock schema = %q", lock.Schema)
	}
	if lock.Policy.Profile != "strict" {
		t.Fatalf("lock profile = %q", lock.Policy.Profile)
	}
	if lock.Name != "clean-skill" {
		t.Fatalf("lock name = %q", lock.Name)
	}

	againPath, againResult, err := installSkillAtomic(src, targetRoot, "clean-skill", report)
	if err != nil {
		t.Fatalf("second install should be idempotent: %v", err)
	}
	if againResult != installResultAlreadyInstalled {
		t.Fatalf("second install result = %q, want %q", againResult, installResultAlreadyInstalled)
	}
	if againPath != installedPath {
		t.Fatalf("second install path = %q, want %q", againPath, installedPath)
	}
}

func TestInstallSkillAtomicAndCopyErrors(t *testing.T) {
	t.Run("install fails for symlink in source tree", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		src := createSkillSourceForInstallTest(t, "symlink-skill")
		if err := os.Symlink("SKILL.md", filepath.Join(src, "link.md")); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		report := installReport{SchemaVersion: "0.1.0-draft", PolicyProfile: "strict", Decision: "PASS"}
		_, _, err := installSkillAtomic(src, targetRoot, "symlink-skill", report)
		if err == nil || !strings.Contains(err.Error(), "contains symlink") {
			t.Fatalf("expected symlink error, got %v", err)
		}
	})

	t.Run("install metadata write fails when report path is directory", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "bad-report-skill")
		if err := os.Mkdir(filepath.Join(src, installReportFile), 0o755); err != nil {
			t.Fatalf("mkdir colliding report path: %v", err)
		}
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		report := installReport{SchemaVersion: "0.1.0-draft", PolicyProfile: "strict", Decision: "PASS"}
		_, _, err := installSkillAtomic(src, targetRoot, "bad-report-skill", report)
		if err == nil || !strings.Contains(err.Error(), "failed to write install report") {
			t.Fatalf("expected report write error, got %v", err)
		}
	})

	t.Run("copyTreeNormalized fails for missing source", func(t *testing.T) {
		err := copyTreeNormalized(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "dst"))
		if err == nil {
			t.Fatal("expected walk error")
		}
	})

	t.Run("install fails when target root is not a directory path", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "notdir-skill")
		targetRootFile := filepath.Join(t.TempDir(), "target-file")
		if err := os.WriteFile(targetRootFile, []byte("x"), 0o644); err != nil {
			t.Fatalf("write target file: %v", err)
		}
		report := installReport{SchemaVersion: "0.1.0-draft", PolicyProfile: "strict", Decision: "PASS"}
		_, _, err := installSkillAtomic(src, targetRootFile, "notdir-skill", report)
		if err == nil || !strings.Contains(err.Error(), "failed to create install staging directory") {
			t.Fatalf("expected staging create error for non-directory target root, got %v", err)
		}
	})

	t.Run("install fails when staging root cannot be created", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "missing-target-root")
		missingTarget := filepath.Join(t.TempDir(), "missing", "skills")
		report := installReport{SchemaVersion: "0.1.0-draft", PolicyProfile: "strict", Decision: "PASS"}
		_, _, err := installSkillAtomic(src, missingTarget, "missing-target-root", report)
		if err == nil || !strings.Contains(err.Error(), "failed to create install staging directory") {
			t.Fatalf("expected staging create error, got %v", err)
		}
	})

	t.Run("copyTreeNormalized fails when destination subpath cannot be created", func(t *testing.T) {
		srcRoot := t.TempDir()
		if err := os.Mkdir(filepath.Join(srcRoot, "skill"), 0o755); err != nil {
			t.Fatalf("mkdir skill: %v", err)
		}
		if err := os.Mkdir(filepath.Join(srcRoot, "skill", "nested"), 0o755); err != nil {
			t.Fatalf("mkdir nested: %v", err)
		}
		if err := os.WriteFile(filepath.Join(srcRoot, "skill", "nested", "file.txt"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}

		dstRoot := filepath.Join(t.TempDir(), "dst")
		if err := os.MkdirAll(dstRoot, 0o755); err != nil {
			t.Fatalf("mkdir dst root: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dstRoot, "nested"), []byte("block"), 0o644); err != nil {
			t.Fatalf("write blocker file: %v", err)
		}

		err := copyTreeNormalized(filepath.Join(srcRoot, "skill"), dstRoot)
		if err == nil || (!strings.Contains(err.Error(), "failed to create install directory") && !strings.Contains(err.Error(), "not a directory")) {
			t.Fatalf("expected install directory creation error, got %v", err)
		}
	})
}

func TestInstallSkillAtomicRejectsDifferentProvenance(t *testing.T) {
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}

	first := createSkillSourceForInstallTest(t, "same-name-skill")
	second := createSkillSourceForInstallTest(t, "same-name-skill")
	if err := os.WriteFile(filepath.Join(second, "README.md"), []byte("different"), 0o644); err != nil {
		t.Fatalf("mutate second source: %v", err)
	}

	firstReport := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: first, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	if _, _, err := installSkillAtomic(first, targetRoot, "same-name-skill", firstReport); err != nil {
		t.Fatalf("first installSkillAtomic() error = %v", err)
	}

	secondReport := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: second, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	_, _, err := installSkillAtomic(second, targetRoot, "same-name-skill", secondReport)
	if err == nil || !strings.Contains(err.Error(), "different provenance") {
		t.Fatalf("expected different provenance rejection, got %v", err)
	}
}

func TestInstallSkillAtomicExistingTargetValidation(t *testing.T) {
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		PolicyProfile: "strict",
		Decision:      "PASS",
	}

	t.Run("existing target path is a file", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "file-target-skill")
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "file-target-skill"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write colliding file: %v", err)
		}

		_, _, err := installSkillAtomic(src, targetRoot, "file-target-skill", report)
		if err == nil || !strings.Contains(err.Error(), "non-directory path") {
			t.Fatalf("expected non-directory path error, got %v", err)
		}
	})

	t.Run("existing target directory without lockfile", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "missing-lock-skill")
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "missing-lock-skill"), 0o755); err != nil {
			t.Fatalf("mkdir colliding dir: %v", err)
		}

		_, _, err := installSkillAtomic(src, targetRoot, "missing-lock-skill", report)
		if err == nil || !strings.Contains(err.Error(), "missing/invalid lockfile") {
			t.Fatalf("expected missing lockfile error, got %v", err)
		}
	})

	t.Run("existing target directory with malformed lockfile structure", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "malformed-lock-skill")
		targetRoot := filepath.Join(t.TempDir(), "skills")
		finalPath := filepath.Join(targetRoot, "malformed-lock-skill")
		if err := os.MkdirAll(finalPath, 0o755); err != nil {
			t.Fatalf("mkdir colliding dir: %v", err)
		}
		malformed := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "malformed-lock-skill",
			InstalledAt: "not-rfc3339",
			Source: lockSource{
				Type:  "local",
				Input: filepath.Clean(src),
				Kind:  "local-dir",
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "pass",
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}
		raw, err := json.MarshalIndent(malformed, "", "  ")
		if err != nil {
			t.Fatalf("marshal malformed lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(finalPath, installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write malformed lock: %v", err)
		}

		_, _, err = installSkillAtomic(src, targetRoot, "malformed-lock-skill", report)
		if err == nil || !strings.Contains(err.Error(), "missing/invalid lockfile") {
			t.Fatalf("expected malformed lockfile rejection, got %v", err)
		}
		if !strings.Contains(err.Error(), "installed_at must be RFC3339") {
			t.Fatalf("expected malformed lockfile detail, got %v", err)
		}
	})

	t.Run("existing target directory with lock/content drift", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "drifted-existing-skill")
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		reportWithSource := installReport{
			SchemaVersion: "0.1.0-draft",
			Source: source{
				Input: src,
				Kind:  "local-dir",
			},
			PolicyProfile: "strict",
			Decision:      "PASS",
		}
		installedPath, _, err := installSkillAtomic(src, targetRoot, "drifted-existing-skill", reportWithSource)
		if err != nil {
			t.Fatalf("first installSkillAtomic() error = %v", err)
		}
		if err := os.WriteFile(filepath.Join(installedPath, "README.md"), []byte("tampered"), 0o644); err != nil {
			t.Fatalf("mutate installed file: %v", err)
		}

		_, _, err = installSkillAtomic(src, targetRoot, "drifted-existing-skill", reportWithSource)
		if err == nil || !strings.Contains(err.Error(), "missing/invalid lockfile") {
			t.Fatalf("expected drifted installed-content rejection, got %v", err)
		}
		if !strings.Contains(err.Error(), "drift detected") {
			t.Fatalf("expected drift detail, got %v", err)
		}
	})

	t.Run("existing target directory with install report drift", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "report-drift-existing-skill")
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		reportWithSource := installReport{
			SchemaVersion: "0.1.0-draft",
			Source: source{
				Input: src,
				Kind:  "local-dir",
			},
			PolicyProfile: "strict",
			Decision:      "PASS",
		}
		installedPath, _, err := installSkillAtomic(src, targetRoot, "report-drift-existing-skill", reportWithSource)
		if err != nil {
			t.Fatalf("first installSkillAtomic() error = %v", err)
		}
		lockPath := filepath.Join(installedPath, installLockFile)
		rawLock, err := os.ReadFile(lockPath)
		if err != nil {
			t.Fatalf("read install lock: %v", err)
		}
		var mut installLock
		if err := json.Unmarshal(rawLock, &mut); err != nil {
			t.Fatalf("unmarshal install lock: %v", err)
		}
		mut.Policy.SeverityOverrides = []severityOverrideAudit{
			{
				RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
				PreviousSeverity:  "high",
				EffectiveSeverity: "medium",
				Justification:     "tamper test",
				ApprovedBy:        "security-reviewer",
				Source:            "policy-file",
				AppliedAt:         "2026-05-24T00:00:00Z",
			},
		}
		mutRaw, err := json.MarshalIndent(mut, "", "  ")
		if err != nil {
			t.Fatalf("marshal tampered install lock: %v", err)
		}
		if err := os.WriteFile(lockPath, mutRaw, 0o644); err != nil {
			t.Fatalf("write tampered install lock: %v", err)
		}

		_, _, err = installSkillAtomic(src, targetRoot, "report-drift-existing-skill", reportWithSource)
		if err == nil || !strings.Contains(err.Error(), "missing/invalid lockfile") {
			t.Fatalf("expected drifted install-report rejection, got %v", err)
		}
		if !strings.Contains(err.Error(), "install report integrity check failed") {
			t.Fatalf("expected install report integrity detail, got %v", err)
		}
	})

	t.Run("existing target path is a symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		src := createSkillSourceForInstallTest(t, "symlink-target-entry-skill")
		base := t.TempDir()
		targetRoot := filepath.Join(base, "skills")
		if err := os.Mkdir(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		realExisting := filepath.Join(base, "real-existing")
		if err := os.Mkdir(realExisting, 0o755); err != nil {
			t.Fatalf("mkdir real existing dir: %v", err)
		}
		if err := os.Symlink("../real-existing", filepath.Join(targetRoot, "symlink-target-entry-skill")); err != nil {
			t.Fatalf("create target entry symlink: %v", err)
		}

		_, _, err := installSkillAtomic(src, targetRoot, "symlink-target-entry-skill", report)
		if err == nil || !strings.Contains(err.Error(), ruleInstallTargetEntrySymlink) {
			t.Fatalf("expected target-entry symlink rejection, got %v", err)
		}
	})
}
