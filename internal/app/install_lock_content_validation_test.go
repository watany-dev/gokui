package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateInstalledContentForIdempotentReuse(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "validate-installed-content")
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
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "validate-installed-content", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}
	lock, err := readInstallLock(filepath.Join(installedPath, installLockFile))
	if err != nil {
		t.Fatalf("readInstallLock() error = %v", err)
	}

	if err := validateInstalledContentForIdempotentReuse(installedPath, lock); err != nil {
		t.Fatalf("validateInstalledContentForIdempotentReuse(valid) error = %v", err)
	}

	if err := os.Remove(filepath.Join(installedPath, "README.md")); err != nil {
		t.Fatalf("remove README.md: %v", err)
	}
	if err := validateInstalledContentForIdempotentReuse(installedPath, lock); err == nil || !strings.Contains(err.Error(), "drift detected") {
		t.Fatalf("expected missing-file drift error, got %v", err)
	}

	// Reinstall fresh copy to isolate report integrity drift test.
	freshSrc := createSkillSourceForInstallTest(t, "validate-installed-content-report")
	freshTargetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(freshTargetRoot, 0o755); err != nil {
		t.Fatalf("mkdir fresh target root: %v", err)
	}
	freshReport := installReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: freshSrc,
			Kind:  "local-dir",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	freshInstalledPath, _, err := installSkillAtomic(freshSrc, freshTargetRoot, "validate-installed-content-report", freshReport)
	if err != nil {
		t.Fatalf("installSkillAtomic(fresh) error = %v", err)
	}
	freshLock, err := readInstallLock(filepath.Join(freshInstalledPath, installLockFile))
	if err != nil {
		t.Fatalf("readInstallLock(fresh) error = %v", err)
	}
	freshLock.Policy.SeverityOverrides = []severityOverrideAudit{
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
	if err := validateInstalledContentForIdempotentReuse(freshInstalledPath, freshLock); err == nil || !strings.Contains(err.Error(), "install report integrity check failed") {
		t.Fatalf("expected install report integrity error, got %v", err)
	}

	// Root hash mismatch branch.
	hashMismatchSrc := createSkillSourceForInstallTest(t, "validate-installed-content-root")
	hashMismatchTarget := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(hashMismatchTarget, 0o755); err != nil {
		t.Fatalf("mkdir hash-mismatch target root: %v", err)
	}
	hashMismatchReport := installReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: hashMismatchSrc,
			Kind:  "local-dir",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	hashMismatchPath, _, err := installSkillAtomic(hashMismatchSrc, hashMismatchTarget, "validate-installed-content-root", hashMismatchReport)
	if err != nil {
		t.Fatalf("installSkillAtomic(hash mismatch) error = %v", err)
	}
	hashMismatchLock, err := readInstallLock(filepath.Join(hashMismatchPath, installLockFile))
	if err != nil {
		t.Fatalf("readInstallLock(hash mismatch) error = %v", err)
	}
	hashMismatchLock.Skill.RootSHA256 = strings.Repeat("c", 64)
	if err := validateInstalledContentForIdempotentReuse(hashMismatchPath, hashMismatchLock); err == nil || !strings.Contains(err.Error(), "root hash drift detected") {
		t.Fatalf("expected root hash drift error, got %v", err)
	}

	// GitHub metadata branch.
	githubSrc := createSkillSourceForInstallTest(t, "validate-installed-content-github")
	githubTarget := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(githubTarget, 0o755); err != nil {
		t.Fatalf("mkdir github target root: %v", err)
	}
	githubReport := installReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: "github:org/repo//skills/validate-installed-content-github@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	githubPath, _, err := installSkillAtomic(githubSrc, githubTarget, "validate-installed-content-github", githubReport)
	if err != nil {
		t.Fatalf("installSkillAtomic(github) error = %v", err)
	}
	githubLock, err := readInstallLock(filepath.Join(githubPath, installLockFile))
	if err != nil {
		t.Fatalf("readInstallLock(github) error = %v", err)
	}
	if err := validateInstalledContentForIdempotentReuse(githubPath, githubLock); err != nil {
		t.Fatalf("validateInstalledContentForIdempotentReuse(github valid) error = %v", err)
	}
	metaPath := filepath.Join(githubPath, sourceMetadataFile)
	metaRaw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read source metadata: %v", err)
	}
	var meta sourceMetadata
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("unmarshal source metadata: %v", err)
	}
	meta.ResolvedRef = "ffffffffffffffffffffffffffffffffffffffff"
	mutMetaRaw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered source metadata: %v", err)
	}
	if err := os.WriteFile(metaPath, mutMetaRaw, 0o644); err != nil {
		t.Fatalf("write tampered source metadata: %v", err)
	}
	filesAfterTamper, rootAfterTamper, err := buildFileDigestsForLock(githubPath)
	if err != nil {
		t.Fatalf("buildFileDigestsForLock(tampered github): %v", err)
	}
	githubLock.Skill.Files = filesAfterTamper
	githubLock.Skill.RootSHA256 = rootAfterTamper
	if err := validateInstalledContentForIdempotentReuse(githubPath, githubLock); err == nil || !strings.Contains(err.Error(), "source metadata drift detected") {
		t.Fatalf("expected github source metadata drift error, got %v", err)
	}
}
