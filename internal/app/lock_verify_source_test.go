package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyLockSourceChecks(t *testing.T) {
	sourceInput := filepath.Clean(filepath.Join(t.TempDir(), "skill"))
	lock := installLock{
		Schema: "gokui.lock/v1",
		Source: lockSource{
			Type:  "local",
			Input: sourceInput,
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
	lock.Source.Input = " " + sourceInput + " "
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("input with surrounding whitespace should fail")
	}
	lock.Source.Input = "/tmp/skill\npayload"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("input with C0 control characters should fail")
	}
	lock.Source.Input = "/tmp/skill\u0085payload"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("input with C1 control characters should fail")
	}
	lock.Source.Input = "\u0085/tmp/skill"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("input with edge C1 control characters should fail")
	}
	lock.Source.Input = "\u0085"
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("input with C1 control characters only should fail")
	} else if !strings.Contains(detail, "must not contain C0/C1 control characters") {
		t.Fatalf("input with C1 control characters only should surface control detail, got %q", detail)
	}
	lock.Source.Input = "\u007f"
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("input with DEL control characters only should fail")
	} else if !strings.Contains(detail, "must not contain C0/C1 control characters") {
		t.Fatalf("input with DEL control characters only should surface control detail, got %q", detail)
	}
	lock.Source.Input = "\u007f/tmp/skill"
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("input with DEL edge control characters should fail")
	} else if !strings.Contains(detail, "must not contain C0/C1 control characters") {
		t.Fatalf("input with DEL edge control characters should surface control detail, got %q", detail)
	}
	lock.Source.Input = sourceInput + "\u200dpayload"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("input with unicode obfuscation characters should fail")
	}
	lock.Source.Input = sourceInput
	lock.Source.Kind = " local-dir "
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind with surrounding whitespace should fail")
	}
	lock.Source.Kind = "local\u008fdir"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind with C0/C1 control characters should fail")
	}
	lock.Source.Kind = "\u0085local-dir"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind with edge C1 control characters should fail")
	}
	lock.Source.Kind = "\u0085"
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("kind with C0/C1 control characters only should fail")
	} else if !strings.Contains(detail, "must not contain C0/C1 control characters") {
		t.Fatalf("kind with C0/C1 control characters only should surface control detail, got %q", detail)
	}
	lock.Source.Kind = "\u007f"
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("kind with DEL control character only should fail")
	} else if !strings.Contains(detail, "must not contain C0/C1 control characters") {
		t.Fatalf("kind with DEL control character only should surface control detail, got %q", detail)
	}
	lock.Source.Kind = "\u007flocal-dir"
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("kind with DEL edge control characters should fail")
	} else if !strings.Contains(detail, "must not contain C0/C1 control characters") {
		t.Fatalf("kind with DEL edge control characters should surface control detail, got %q", detail)
	}
	lock.Source.Kind = "local-dir\u200d"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind with unicode obfuscation characters should fail")
	}
	lock.Source.Kind = "LOCAL-DIR"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind with uppercase letters should fail")
	}
	lock.Source.Kind = "local-dir"
	lock.Source.Input = sourceInput
	lock.Source.Type = ""
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("empty source type should fail")
	} else if !strings.Contains(detail, "lock source type is empty") {
		t.Fatalf("empty source type should surface empty detail, got %q", detail)
	}
	lock.Source.Type = "local"
	lock.Source.Type = " local "
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type with surrounding whitespace should fail")
	}
	lock.Source.Type = "loca\u008fl"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type with C0/C1 control characters should fail")
	}
	lock.Source.Type = "\u0085local"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type with edge C1 control characters should fail")
	}
	lock.Source.Type = "\u007f"
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("type with DEL control characters only should fail")
	} else if !strings.Contains(detail, "must not contain C0/C1 control characters") {
		t.Fatalf("type with DEL control characters only should surface control detail, got %q", detail)
	}
	lock.Source.Type = "\u007flocal"
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("type with DEL edge control characters should fail")
	} else if !strings.Contains(detail, "must not contain C0/C1 control characters") {
		t.Fatalf("type with DEL edge control characters should surface control detail, got %q", detail)
	}
	lock.Source.Type = "local\u200d"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type with unicode obfuscation characters should fail")
	}
	lock.Source.Type = "LOCAL"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type with uppercase letters should fail")
	}
	lock.Source.Type = "local"
	lock.Source.Input = "/tmp/skill/../skill"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("non-canonical local input path should fail")
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

	lock.Source.Type = "local"
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	lock.Source.Kind = "local-dir"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind/input mismatch should fail")
	}

	lock.Source.Kind = "github-source"
	lock.Source.Type = "github"
	lock.Source.Input = "github:org/repo/path@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("invalid github source syntax should fail")
	}
	lock.Source.Input = "github:owner_name/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("invalid github owner format should fail")
	}
	lock.Source.Input = "github:Owner/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("uppercase github owner should fail")
	}
	lock.Source.Input = "github:owner/Repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("uppercase github repo should fail")
	}
	lock.Source.Input = "github:owner/.repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("leading-dot github repo should fail")
	}
	lock.Source.Input = "github:owner/repo.//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("trailing-dot github repo should fail")
	}
	lock.Source.Input = "github:owner/repo.git//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github repo .git suffix should fail")
	}
	lock.Source.Input = "github:owner/re..po//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github repo consecutive dots should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@shadow@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with @ in path should fail")
	}
	lock.Source.Input = "github:org/repo//skills:demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with : in path should fail")
	}
	lock.Source.Input = "github:org/repo//skills/con@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with reserved device path segment should fail")
	}
	lock.Source.Input = "github:org/repo//skills/COM¹.txt@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with reserved superscript-device path segment should fail")
	}
	lock.Source.Input = "github:org/repo//skills/\u202edemo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path bidi-control should fail")
	}
	lock.Source.Input = "github:org/repo//skills/\u200bdemo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path zero-width char should fail")
	}
	lock.Source.Input = "github:org/repo//skills/my skill@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path whitespace char should fail")
	}
	lock.Source.Input = "github:org/repo//skills/ demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path-segment leading space should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo.@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path-segment trailing dot should fail")
	}
	lock.Source.Input = "github:org/repo//skills/./demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("non-canonical github source input should fail")
	}
	lock.Source.Input = "github:org/repo// skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path surrounding spaces should fail")
	}
	lock.Source.Input = "github:org/repo//skills//demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with non-canonical path segments should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\u00a01234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with unicode-whitespace ref should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\u00851234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with C1 control ref should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\u200b1234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with zero-width ref should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\u202e1234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with bidi-control ref should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\U000E00011234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with unicode-tag ref should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\ufe0f1234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with variation-selector ref should fail")
	}
	lock.Source.Input = "github:or\u00a0g/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with owner unicode-whitespace should fail")
	}
	lock.Source.Input = "github:org/re\u200bpo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with repo zero-width should fail")
	}
	lock.Source.Input = "github:or\U000E0001g/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with owner unicode tag should fail")
	}
	lock.Source.Input = "github:org/re\ufe0fpo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with repo variation-selector should fail")
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
