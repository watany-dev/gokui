package app

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/quick"

	"github.com/watany-dev/gokui/internal/limitio"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

func TestBuildFileDigestsAndSourceType(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatalf("write b.txt: %v", err)
	}

	files, rootHash, err := buildFileDigestsFiltered(root, nil)
	if err != nil {
		t.Fatalf("buildFileDigests() error = %v", err)
	}
	if len(files) != 2 || rootHash == "" {
		t.Fatalf("unexpected digests files=%d rootHash=%q", len(files), rootHash)
	}

	if sourceTypeFromKind("local-dir") != "local" {
		t.Fatal("local-dir should map to local")
	}
	if sourceTypeFromKind("zip") != "archive" {
		t.Fatal("zip should map to archive")
	}
	if sourceTypeFromKind("github-source") != "github" {
		t.Fatal("github-source should map to github")
	}
	if sourceTypeFromKind("x") != "unknown" {
		t.Fatal("unknown kind should map to unknown")
	}
}

func TestCopyFileWithModeAndHashErrors(t *testing.T) {
	t.Run("copyFileWithMode source missing", func(t *testing.T) {
		_, err := limitio.CopyFileWithModeChecked(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "out"), 0o644, 1024, nil, ensureInstallSourceStableFromOpen)
		if err == nil || !strings.Contains(err.Error(), "failed to open source file") {
			t.Fatalf("expected source-open error, got %v", err)
		}
	})

	t.Run("copyFileWithMode destination create failure", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "src.txt")
		if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
			t.Fatalf("write src: %v", err)
		}
		dst := filepath.Join(t.TempDir(), "dir")
		if err := os.Mkdir(dst, 0o755); err != nil {
			t.Fatalf("mkdir dst dir: %v", err)
		}
		_, err := limitio.CopyFileWithModeChecked(src, dst, 0o644, 1024, nil, ensureInstallSourceStableFromOpen)
		if err == nil || !strings.Contains(err.Error(), "failed to create destination file") {
			t.Fatalf("expected destination create error, got %v", err)
		}
	})

	t.Run("copyFileWithMode enforces max bytes", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "src.txt")
		if err := os.WriteFile(src, []byte("xx"), 0o644); err != nil {
			t.Fatalf("write src: %v", err)
		}
		dst := filepath.Join(t.TempDir(), "out.txt")
		_, err := limitio.CopyFileWithModeChecked(src, dst, 0o644, 1, nil, ensureInstallSourceStableFromOpen)
		if err == nil || !errors.Is(err, limitio.ErrSizeExceeded) {
			t.Fatalf("expected max-bytes copy error, got %v", err)
		}
		if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
			t.Fatalf("oversized destination file should be removed, stat err=%v", statErr)
		}
	})

	t.Run("copyFileWithMode removes destination on copy read error", func(t *testing.T) {
		srcDir := t.TempDir()
		dst := filepath.Join(t.TempDir(), "out.txt")
		_, err := limitio.CopyFileWithModeChecked(srcDir, dst, 0o644, 1024, nil, ensureInstallSourceStableFromOpen)
		if err == nil {
			t.Fatalf("expected copy read error, got %v", err)
		}
		if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
			t.Fatalf("destination file should be removed on copy error, stat err=%v", statErr)
		}
	})

	t.Run("copyFileWithMode returns written bytes on success", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "src.txt")
		if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
			t.Fatalf("write src: %v", err)
		}
		dst := filepath.Join(t.TempDir(), "out.txt")
		written, err := limitio.CopyFileWithModeChecked(src, dst, 0o640, 1024, nil, ensureInstallSourceStableFromOpen)
		if err != nil {
			t.Fatalf("limitio.CopyFileWithModeChecked() error = %v", err)
		}
		if written != 5 {
			t.Fatalf("written = %d, want 5", written)
		}
		out, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("read dst: %v", err)
		}
		if string(out) != "hello" {
			t.Fatalf("destination contents = %q", string(out))
		}
	})

	t.Run("copyFileWithModeChecked detects source replacement", func(t *testing.T) {
		root := t.TempDir()
		first := filepath.Join(root, "first.txt")
		if err := os.WriteFile(first, []byte("one"), 0o644); err != nil {
			t.Fatalf("write first: %v", err)
		}
		second := filepath.Join(root, "second.txt")
		if err := os.WriteFile(second, []byte("two"), 0o644); err != nil {
			t.Fatalf("write second: %v", err)
		}
		firstInfo, err := os.Lstat(first)
		if err != nil {
			t.Fatalf("lstat first: %v", err)
		}

		dst := filepath.Join(root, "out.txt")
		_, err = limitio.CopyFileWithModeChecked(second, dst, 0o644, 1024, firstInfo, ensureInstallSourceStableFromOpen)
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallSourceChangedDuringCopy.ID) {
			t.Fatalf("expected source-changed copy error, got %v", err)
		}
		if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
			t.Fatalf("destination should not be created on source-changed error, stat err=%v", statErr)
		}
	})

	t.Run("ensureInstallSourceStableFromOpen handles stat errors", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "src.txt")
		if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
			t.Fatalf("write src: %v", err)
		}
		info, err := os.Lstat(src)
		if err != nil {
			t.Fatalf("lstat src: %v", err)
		}
		if err := ensureInstallSourceStableFromOpen(info, installErrorStatter{err: errors.New("stat fail")}, src); err == nil || !strings.Contains(err.Error(), "failed to open source file") {
			t.Fatalf("expected source stat error, got %v", err)
		}
	})

	t.Run("hashFile source missing", func(t *testing.T) {
		_, _, err := limitio.HashSHA256FileWithLimitChecked(filepath.Join(t.TempDir(), "missing"), installMaxDigestFileBytes, nil, ensureInstallDigestStableFromOpen)
		if err == nil || !strings.Contains(err.Error(), "failed to open file for hashing") {
			t.Fatalf("expected hash open error, got %v", err)
		}
	})

	t.Run("hashFileWithLimit detects overflow", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "data.bin")
		if err := os.WriteFile(path, []byte("ab"), 0o644); err != nil {
			t.Fatalf("write data: %v", err)
		}
		_, _, err := limitio.HashSHA256FileWithLimitChecked(path, 1, nil, ensureInstallDigestStableFromOpen)
		if err == nil || !errors.Is(err, limitio.ErrSizeExceeded) {
			t.Fatalf("expected size exceeded error, got %v", err)
		}
	})

	t.Run("hashFileWithLimitChecked detects source replacement", func(t *testing.T) {
		root := t.TempDir()
		first := filepath.Join(root, "first.bin")
		if err := os.WriteFile(first, []byte("one"), 0o644); err != nil {
			t.Fatalf("write first: %v", err)
		}
		second := filepath.Join(root, "second.bin")
		if err := os.WriteFile(second, []byte("two"), 0o644); err != nil {
			t.Fatalf("write second: %v", err)
		}
		firstInfo, err := os.Lstat(first)
		if err != nil {
			t.Fatalf("lstat first: %v", err)
		}
		_, _, err = limitio.HashSHA256FileWithLimitChecked(second, 1024, firstInfo, ensureInstallDigestStableFromOpen)
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallDigestSourceChangedDuringHash.ID) {
			t.Fatalf("expected digest source-changed error, got %v", err)
		}
	})

	t.Run("ensureInstallDigestStableFromOpen handles stat errors", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "data.bin")
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("write data: %v", err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("lstat data: %v", err)
		}
		if err := ensureInstallDigestStableFromOpen(info, installErrorStatter{err: errors.New("stat fail")}, path); err == nil || !strings.Contains(err.Error(), "failed to open file for hashing") {
			t.Fatalf("expected digest stat error, got %v", err)
		}
	})
}

func TestCopyWithStrictLimitProperty(t *testing.T) {
	prop := func(data []byte, limit uint16) bool {
		maxBytes := int64(limit)
		var out bytes.Buffer
		written, err := limitio.CopyWithStrictLimit(&out, bytes.NewReader(data), maxBytes)
		if int64(out.Len()) != written {
			return false
		}
		if written > maxBytes {
			return false
		}
		if int64(len(data)) <= maxBytes {
			if err != nil {
				return false
			}
			return bytes.Equal(out.Bytes(), data)
		}
		if err == nil || !strings.Contains(err.Error(), "size exceeds limit") {
			return false
		}
		if out.Len() != int(maxBytes) {
			return false
		}
		return bytes.Equal(out.Bytes(), data[:maxBytes])
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatalf("copyWithStrictLimit property failed: %v", err)
	}
}

func TestCopyWithStrictLimitEdgeCases(t *testing.T) {
	t.Run("rejects negative limit", func(t *testing.T) {
		var out bytes.Buffer
		_, err := limitio.CopyWithStrictLimit(&out, bytes.NewReader([]byte("x")), -1)
		if err == nil || !strings.Contains(err.Error(), "size exceeds limit") {
			t.Fatalf("expected negative-limit error, got %v", err)
		}
	})

	t.Run("zero limit accepts empty input", func(t *testing.T) {
		var out bytes.Buffer
		written, err := limitio.CopyWithStrictLimit(&out, bytes.NewReader(nil), 0)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if written != 0 || out.Len() != 0 {
			t.Fatalf("expected zero write, got written=%d len=%d", written, out.Len())
		}
	})

	t.Run("zero limit rejects non-empty input", func(t *testing.T) {
		var out bytes.Buffer
		_, err := limitio.CopyWithStrictLimit(&out, bytes.NewReader([]byte("x")), 0)
		if err == nil || !strings.Contains(err.Error(), "size exceeds limit") {
			t.Fatalf("expected size-limit error, got %v", err)
		}
	})

	t.Run("propagates destination write errors", func(t *testing.T) {
		dst := &failingWriter{failAfter: 0}
		_, err := limitio.CopyWithStrictLimit(dst, bytes.NewReader([]byte("abc")), 10)
		if err == nil || !strings.Contains(err.Error(), "write failed") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("returns short write when destination truncates", func(t *testing.T) {
		dst := &shortWriter{}
		_, err := limitio.CopyWithStrictLimit(dst, bytes.NewReader([]byte("abc")), 10)
		if err == nil || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("expected io.ErrShortWrite, got %v", err)
		}
	})

	t.Run("propagates reader errors", func(t *testing.T) {
		src := &failingReader{
			data:      []byte("abc"),
			failAfter: 1,
			err:       errors.New("read failed"),
		}
		var out bytes.Buffer
		_, err := limitio.CopyWithStrictLimit(&out, src, 1)
		if err == nil || !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("returns written bytes before reader error in same read", func(t *testing.T) {
		src := &partialErrReader{
			data: []byte("abc"),
			err:  errors.New("read failed"),
		}
		var out bytes.Buffer
		written, err := limitio.CopyWithStrictLimit(&out, src, 10)
		if err == nil || !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("expected read error, got %v", err)
		}
		if written != int64(out.Len()) || written == 0 {
			t.Fatalf("expected partial write before error, written=%d len=%d", written, out.Len())
		}
	})
}

type failingWriter struct {
	failAfter int
	writes    int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.writes >= w.failAfter {
		return 0, errors.New("write failed")
	}
	w.writes++
	return len(p), nil
}

type shortWriter struct{}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

type failingReader struct {
	data      []byte
	offset    int
	failAfter int
	err       error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	if r.offset >= r.failAfter {
		return 0, r.err
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

type partialErrReader struct {
	data []byte
	read bool
	err  error
}

func (r *partialErrReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	n := copy(p, r.data)
	return n, r.err
}

func TestBuildLockSummaryCounts(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "summary-skill")
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: src,
			Kind:  "zip",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
		SeverityOverrides: []severityOverrideAudit{
			{
				RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
				PreviousSeverity:  "high",
				EffectiveSeverity: "medium",
				Justification:     "approved for controlled environment",
				ApprovedBy:        "security-reviewer",
				Source:            "policy-file",
				AppliedAt:         "2026-05-24T00:00:00Z",
			},
		},
		Findings: []inspectFinding{
			{ID: "A", Severity: "critical"},
			{ID: "B", Severity: "high"},
			{ID: "C", Severity: "medium"},
			{ID: "D", Severity: "low"},
		},
	}
	lock, err := buildInstallLock(src, report)
	if err != nil {
		t.Fatalf("buildInstallLock() error = %v", err)
	}
	if lock.Findings.Critical != 1 || lock.Findings.High != 1 || lock.Findings.Medium != 1 || lock.Findings.Low != 1 {
		t.Fatalf("unexpected finding summary: %+v", lock.Findings)
	}
	if len(lock.Policy.SeverityOverrides) != 1 {
		t.Fatalf("severity_overrides length = %d, want 1", len(lock.Policy.SeverityOverrides))
	}
	if lock.Policy.SeverityOverrides[0].RuleID != "PROMPT_OVERRIDE_LANGUAGE" {
		t.Fatalf("severity override rule_id = %q", lock.Policy.SeverityOverrides[0].RuleID)
	}
}

func TestWriteInstallMetadataAndBuildDigestsErrors(t *testing.T) {
	t.Run("writeInstallMetadata fails on lock path collision", func(t *testing.T) {
		stage := createSkillSourceForInstallTest(t, "collision-skill")
		if err := os.Mkdir(filepath.Join(stage, installLockFile), 0o755); err != nil {
			t.Fatalf("mkdir lock collision: %v", err)
		}
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source:        source{Input: stage, Kind: "local-dir"},
			PolicyProfile: "strict",
			Decision:      "PASS",
		}
		err := writeInstallMetadata(stage, report)
		if err == nil || !strings.Contains(err.Error(), "failed to write install lockfile") {
			t.Fatalf("expected lockfile write error, got %v", err)
		}
	})

	t.Run("writeInstallMetadata fails when lock build fails", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission behavior differs on windows")
		}

		stage := createSkillSourceForInstallTest(t, "hash-fail-skill")
		blocked := filepath.Join(stage, "blocked.bin")
		if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
			t.Fatalf("write blocked file: %v", err)
		}
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatalf("chmod blocked file: %v", err)
		}
		defer os.Chmod(blocked, 0o644)

		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source:        source{Input: stage, Kind: "local-dir"},
			PolicyProfile: "strict",
			Decision:      "PASS",
		}
		err := writeInstallMetadata(stage, report)
		if err == nil || !strings.Contains(err.Error(), "failed to digest installed files") {
			t.Fatalf("expected digest error, got %v", err)
		}
	})

	t.Run("buildFileDigests fails when file is unreadable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission behavior differs on windows")
		}
		root := t.TempDir()
		file := filepath.Join(root, "blocked.txt")
		if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
			t.Fatalf("write blocked file: %v", err)
		}
		if err := os.Chmod(file, 0o000); err != nil {
			t.Fatalf("chmod blocked file: %v", err)
		}
		defer os.Chmod(file, 0o644)

		_, _, err := buildFileDigestsFiltered(root, nil)
		if err == nil || !strings.Contains(err.Error(), "failed to open file for hashing") {
			t.Fatalf("expected digest read error, got %v", err)
		}
	})

	t.Run("buildFileDigests fails when root directory is missing", func(t *testing.T) {
		_, _, err := buildFileDigestsFiltered(filepath.Join(t.TempDir(), "missing"), nil)
		if err == nil || !strings.Contains(err.Error(), "failed to digest installed files") {
			t.Fatalf("expected walk error, got %v", err)
		}
	})

	t.Run("buildFileDigests rejects symlink entries", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}
		root := t.TempDir()
		target := filepath.Join(root, "target.txt")
		if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
			t.Fatalf("write target: %v", err)
		}
		if err := os.Symlink("target.txt", filepath.Join(root, "link.txt")); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		_, _, err := buildFileDigestsFiltered(root, nil)
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallDigestSymlink.ID) {
			t.Fatalf("expected digest symlink error, got %v", err)
		}
	})

	t.Run("buildFileDigests rejects symlink root", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}
		parent := t.TempDir()
		realRoot := filepath.Join(parent, "real-root")
		if err := os.Mkdir(realRoot, 0o755); err != nil {
			t.Fatalf("mkdir real root: %v", err)
		}
		if err := os.WriteFile(filepath.Join(realRoot, "a.txt"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		linkRoot := filepath.Join(parent, "root-link")
		if err := os.Symlink("real-root", linkRoot); err != nil {
			t.Fatalf("create root symlink: %v", err)
		}
		_, _, err := buildFileDigestsFiltered(linkRoot, nil)
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallDigestSymlink.ID) {
			t.Fatalf("expected digest symlink-root error, got %v", err)
		}
	})

	t.Run("buildFileDigests rejects non-directory root", func(t *testing.T) {
		rootFile := filepath.Join(t.TempDir(), "not-a-dir.txt")
		if err := os.WriteFile(rootFile, []byte("x"), 0o644); err != nil {
			t.Fatalf("write root file: %v", err)
		}
		_, _, err := buildFileDigestsFiltered(rootFile, nil)
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallDigestSpecialFile.ID) {
			t.Fatalf("expected digest non-directory root error, got %v", err)
		}
	})

	t.Run("buildFileDigests rejects special file entries", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("fifo behavior differs on windows")
		}
		root := t.TempDir()
		fifo := filepath.Join(root, "pipe.fifo")
		if err := mkfifoForTest(fifo, 0o600); err != nil {
			t.Fatalf("mkfifo: %v", err)
		}
		_, _, err := buildFileDigestsFiltered(root, nil)
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallDigestSpecialFile.ID) {
			t.Fatalf("expected digest special-file error, got %v", err)
		}
	})

	t.Run("buildFileDigests enforces max file count", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644); err != nil {
			t.Fatalf("write a.txt: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("b"), 0o644); err != nil {
			t.Fatalf("write b.txt: %v", err)
		}
		_, _, err := buildFileDigestsFilteredWithLimits(root, nil, installDigestLimits{MaxFiles: 1, MaxTotalBytes: installMaxDigestTotalBytes, MaxFileBytes: installMaxDigestFileBytes})
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallDigestFileCountExceeded.ID) {
			t.Fatalf("expected max-file-count digest error, got %v", err)
		}
	})

	t.Run("buildFileDigests enforces max total bytes", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("ab"), 0o644); err != nil {
			t.Fatalf("write a.txt: %v", err)
		}
		_, _, err := buildFileDigestsFilteredWithLimits(root, nil, installDigestLimits{MaxFiles: installMaxDigestFiles, MaxTotalBytes: 1, MaxFileBytes: installMaxDigestFileBytes})
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallDigestTotalBytesExceeded.ID) {
			t.Fatalf("expected max-total-bytes digest error, got %v", err)
		}
	})

	t.Run("buildFileDigests enforces max file bytes", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("ab"), 0o644); err != nil {
			t.Fatalf("write a.txt: %v", err)
		}
		_, _, err := buildFileDigestsFilteredWithLimits(root, nil, installDigestLimits{MaxFiles: installMaxDigestFiles, MaxTotalBytes: installMaxDigestTotalBytes, MaxFileBytes: 1})
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallDigestFileTooLarge.ID) {
			t.Fatalf("expected max-file-bytes digest error, got %v", err)
		}
	})

	t.Run("buildInstallLock propagates digest errors", func(t *testing.T) {
		_, err := buildInstallLock(filepath.Join(t.TempDir(), "missing"), installReport{})
		if err == nil || !strings.Contains(err.Error(), "failed to digest installed files") {
			t.Fatalf("expected digest propagation error, got %v", err)
		}
	})
}

func TestHashFileCopyError(t *testing.T) {
	dir := t.TempDir()
	_, _, err := limitio.HashSHA256FileWithLimitChecked(dir, installMaxDigestFileBytes, nil, ensureInstallDigestStableFromOpen)
	if err == nil || !strings.Contains(err.Error(), "failed to hash file") {
		t.Fatalf("expected hash copy error for directory input, got %v", err)
	}
}
