package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyLockSchemaControlCharactersDetail(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "verify-schema-control-char")
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
	installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-schema-control-char", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lockPath := filepath.Join(installedPath, installLockFile)
	lock, err := readInstallLock(lockPath)
	if err != nil {
		t.Fatalf("readInstallLock(valid) error = %v", err)
	}
	lock.Schema = "gokui.lock/v1\u008f"
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	if err := os.WriteFile(lockPath, raw, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	verifyReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if verifyReport.Status != "DRIFTED" {
		t.Fatalf("verify status = %q, want DRIFTED", verifyReport.Status)
	}
	assertCheckFailedContains(t, verifyReport.Checks, "schema", "must not contain C0/C1 control characters")
}

func TestVerifyLockSchemaControlCharactersEdgeDetail(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "verify-schema-control-char-edge")
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
	installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-schema-control-char-edge", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lockPath := filepath.Join(installedPath, installLockFile)
	lock, err := readInstallLock(lockPath)
	if err != nil {
		t.Fatalf("readInstallLock(valid) error = %v", err)
	}
	lock.Schema = "\u0085gokui.lock/v1"
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	if err := os.WriteFile(lockPath, raw, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	verifyReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if verifyReport.Status != "DRIFTED" {
		t.Fatalf("verify status = %q, want DRIFTED", verifyReport.Status)
	}
	assertCheckFailedContains(t, verifyReport.Checks, "schema", "must not contain C0/C1 control characters")
}

func TestVerifyLockSchemaWhitespaceDetail(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "verify-schema-whitespace")
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
	installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-schema-whitespace", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lockPath := filepath.Join(installedPath, installLockFile)
	lock, err := readInstallLock(lockPath)
	if err != nil {
		t.Fatalf("readInstallLock(valid) error = %v", err)
	}
	lock.Schema = " gokui.lock/v1 "
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	if err := os.WriteFile(lockPath, raw, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	verifyReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if verifyReport.Status != "DRIFTED" {
		t.Fatalf("verify status = %q, want DRIFTED", verifyReport.Status)
	}
	assertCheckFailedContains(t, verifyReport.Checks, "schema", "must not contain leading or trailing whitespace")
}

func TestVerifyLockSchemaUnicodeCharactersDetail(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "verify-schema-unicode-char")
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
	installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-schema-unicode-char", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lockPath := filepath.Join(installedPath, installLockFile)
	lock, err := readInstallLock(lockPath)
	if err != nil {
		t.Fatalf("readInstallLock(valid) error = %v", err)
	}
	lock.Schema = "gokui.lock/v1\u200d"
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	if err := os.WriteFile(lockPath, raw, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	verifyReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if verifyReport.Status != "DRIFTED" {
		t.Fatalf("verify status = %q, want DRIFTED", verifyReport.Status)
	}
	assertCheckFailedContains(t, verifyReport.Checks, "schema", "must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
}
