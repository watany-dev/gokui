package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

func TestReadInstallLockAndProvenanceMatches(t *testing.T) {
	base := installLock{
		Schema: "gokui.lock/v1",
		Name:   "skill",
		Source: lockSource{
			Type:  "local",
			Input: "/tmp/skill",
			Kind:  "local-dir",
		},
		Skill: lockSkill{
			RootSHA256: "abc",
		},
		Policy: lockPolicy{
			Profile:  "strict",
			Decision: "pass",
		},
	}

	t.Run("readInstallLock success and failures", func(t *testing.T) {
		dir := t.TempDir()
		okPath := filepath.Join(dir, "ok.lock")
		raw, err := json.Marshal(base)
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(okPath, raw, 0o644); err != nil {
			t.Fatalf("write ok lock: %v", err)
		}

		got, err := readInstallLock(okPath)
		if err != nil {
			t.Fatalf("readInstallLock(ok) error = %v", err)
		}
		if got.Schema != "gokui.lock/v1" || got.Name != "skill" {
			t.Fatalf("unexpected lock: %+v", got)
		}

		badJSON := filepath.Join(dir, "bad-json.lock")
		if err := os.WriteFile(badJSON, []byte("{"), 0o644); err != nil {
			t.Fatalf("write bad json lock: %v", err)
		}
		if _, err := readInstallLock(badJSON); err == nil || !strings.Contains(err.Error(), "invalid install lockfile JSON") {
			t.Fatalf("expected invalid JSON error, got %v", err)
		}

		invalidUTF8Path := filepath.Join(dir, "invalid-utf8.lock")
		invalidUTF8 := append([]byte(`{"schema":"gokui.lock/v1","name":"skill","source":{"type":"local","input":"/tmp/skill","kind":"local-dir"},"skill":{"root_sha256":"abc"},"policy":{"profile":"strict","decision":"pass"},"note":"`), 0xff)
		invalidUTF8 = append(invalidUTF8, []byte(`"}`)...)
		if err := os.WriteFile(invalidUTF8Path, invalidUTF8, 0o644); err != nil {
			t.Fatalf("write invalid utf-8 lock: %v", err)
		}
		if _, err := readInstallLock(invalidUTF8Path); err == nil || !strings.Contains(err.Error(), rulepkg.LockfileInvalidUTF8.ID) {
			t.Fatalf("expected invalid utf-8 lockfile error, got %v", err)
		}

		badSchema := base
		badSchema.Schema = "gokui.lock/v0"
		badSchemaRaw, err := json.Marshal(badSchema)
		if err != nil {
			t.Fatalf("marshal bad schema lock: %v", err)
		}
		badSchemaPath := filepath.Join(dir, "bad-schema.lock")
		if err := os.WriteFile(badSchemaPath, badSchemaRaw, 0o644); err != nil {
			t.Fatalf("write bad schema lock: %v", err)
		}
		if _, err := readInstallLock(badSchemaPath); err == nil || !strings.Contains(err.Error(), "unsupported install lockfile schema") {
			t.Fatalf("expected unsupported schema error, got %v", err)
		}

		badWhitespaceSchema := base
		badWhitespaceSchema.Schema = " gokui.lock/v1 "
		badWhitespaceSchemaRaw, err := json.Marshal(badWhitespaceSchema)
		if err != nil {
			t.Fatalf("marshal bad whitespace schema lock: %v", err)
		}
		badWhitespaceSchemaPath := filepath.Join(dir, "bad-whitespace-schema.lock")
		if err := os.WriteFile(badWhitespaceSchemaPath, badWhitespaceSchemaRaw, 0o644); err != nil {
			t.Fatalf("write bad whitespace schema lock: %v", err)
		}
		if _, err := readInstallLock(badWhitespaceSchemaPath); err == nil || !strings.Contains(err.Error(), "install lockfile schema must not contain leading or trailing whitespace") {
			t.Fatalf("expected whitespace schema error, got %v", err)
		}

		badUnicodeSchema := base
		badUnicodeSchema.Schema = "gokui.lock/v1\u200d"
		badUnicodeSchemaRaw, err := json.Marshal(badUnicodeSchema)
		if err != nil {
			t.Fatalf("marshal bad unicode schema lock: %v", err)
		}
		badUnicodeSchemaPath := filepath.Join(dir, "bad-unicode-schema.lock")
		if err := os.WriteFile(badUnicodeSchemaPath, badUnicodeSchemaRaw, 0o644); err != nil {
			t.Fatalf("write bad unicode schema lock: %v", err)
		}
		if _, err := readInstallLock(badUnicodeSchemaPath); err == nil || !strings.Contains(err.Error(), "install lockfile schema must not contain Unicode bidi, zero-width, tag, or variation-selector characters") {
			t.Fatalf("expected unicode schema error, got %v", err)
		}

		if _, err := readInstallLock(filepath.Join(dir, "missing.lock")); err == nil || !strings.Contains(err.Error(), "failed to read install lockfile") {
			t.Fatalf("expected read error for missing lockfile, got %v", err)
		}

		lockDirPath := filepath.Join(dir, "lock-dir")
		if err := os.Mkdir(lockDirPath, 0o755); err != nil {
			t.Fatalf("mkdir lock-dir: %v", err)
		}
		if _, err := readInstallLock(lockDirPath); err == nil || !strings.Contains(err.Error(), rulepkg.LockfileSpecialFile.ID) {
			t.Fatalf("expected special-file error for directory lockfile path, got %v", err)
		}

		if runtime.GOOS != "windows" {
			target := filepath.Join(dir, "real.lock")
			if err := os.WriteFile(target, raw, 0o644); err != nil {
				t.Fatalf("write real lock: %v", err)
			}
			symlink := filepath.Join(dir, "symlink.lock")
			if err := os.Symlink("real.lock", symlink); err != nil {
				t.Fatalf("create lock symlink: %v", err)
			}
			if _, err := readInstallLock(symlink); err == nil || !strings.Contains(err.Error(), rulepkg.LockfileSymlink.ID) {
				t.Fatalf("expected lockfile symlink rejection, got %v", err)
			}

			realParent := filepath.Join(dir, "real-parent")
			if err := os.Mkdir(realParent, 0o755); err != nil {
				t.Fatalf("mkdir real parent: %v", err)
			}
			realNested := filepath.Join(realParent, "nested")
			if err := os.Mkdir(realNested, 0o755); err != nil {
				t.Fatalf("mkdir real nested: %v", err)
			}
			realNestedLock := filepath.Join(realNested, "nested.lock")
			if err := os.WriteFile(realNestedLock, raw, 0o644); err != nil {
				t.Fatalf("write nested lock: %v", err)
			}
			linkParent := filepath.Join(dir, "link-parent")
			if err := os.Symlink("real-parent", linkParent); err != nil {
				t.Fatalf("create parent symlink: %v", err)
			}
			if _, err := readInstallLock(filepath.Join(linkParent, "nested", "nested.lock")); err == nil || !strings.Contains(err.Error(), rulepkg.LockfileSymlink.ID) {
				t.Fatalf("expected ancestor symlink lockfile rejection, got %v", err)
			}
		}

		oversizedPath := filepath.Join(dir, "oversized.lock")
		if err := os.WriteFile(oversizedPath, []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
			t.Fatalf("write oversized lock: %v", err)
		}
		if _, err := readInstallLockWithLimit(oversizedPath, 8); err == nil || !strings.Contains(err.Error(), rulepkg.LockfileTooLarge.ID) {
			t.Fatalf("expected oversized lockfile error, got %v", err)
		}

		firstInfo, err := os.Lstat(okPath)
		if err != nil {
			t.Fatalf("lstat ok lock: %v", err)
		}
		if err := ensureInstallLockStableFromOpen(firstInfo, installErrorStatter{err: errors.New("stat fail")}, okPath); err == nil || !strings.Contains(err.Error(), "failed to read install lockfile") {
			t.Fatalf("expected install lock stat error, got %v", err)
		}

		opened, err := os.Open(okPath)
		if err != nil {
			t.Fatalf("open ok lock: %v", err)
		}
		defer opened.Close()

		if err := ensureInstallLockStableFromOpen(firstInfo, opened, okPath); err != nil {
			t.Fatalf("same install lock identity should pass, got %v", err)
		}

		secondPath := filepath.Join(dir, "other.lock")
		if err := os.WriteFile(secondPath, raw, 0o644); err != nil {
			t.Fatalf("write second lock: %v", err)
		}
		secondOpened, err := os.Open(secondPath)
		if err != nil {
			t.Fatalf("open second lock: %v", err)
		}
		defer secondOpened.Close()
		if err := ensureInstallLockStableFromOpen(firstInfo, secondOpened, secondPath); err == nil || !strings.Contains(err.Error(), rulepkg.LockfileSourceChangedDuringRead.ID) {
			t.Fatalf("expected source-changed install lock error, got %v", err)
		}
	})

	t.Run("provenanceMatches true and false cases", func(t *testing.T) {
		if !provenanceMatches(base, base) {
			t.Fatal("expected matching provenance")
		}

		mut := base
		mut.Schema = "other"
		if provenanceMatches(base, mut) {
			t.Fatal("schema mismatch should fail")
		}

		mut = base
		mut.Name = "other"
		if provenanceMatches(base, mut) {
			t.Fatal("name mismatch should fail")
		}

		mut = base
		mut.Source.Input = "/other"
		if provenanceMatches(base, mut) {
			t.Fatal("source mismatch should fail")
		}

		mut = base
		mut.Policy.Profile = "team"
		if provenanceMatches(base, mut) {
			t.Fatal("profile mismatch should fail")
		}

		mut = base
		mut.Skill.RootSHA256 = "def"
		if provenanceMatches(base, mut) {
			t.Fatal("root hash mismatch should fail")
		}
	})

}
