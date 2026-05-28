package materialize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractArchiveZipLimits(t *testing.T) {
	t.Run("handles directory entries", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "dir-entry.zip")
		createZipWithHeaders(t, src, []zipEntry{
			{name: "skill/", mode: 0o755 | os.ModeDir},
			{name: "skill/SKILL.md", body: "---\nname: skill\ndescription: d\n---\n"},
		})

		dest := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		if err := ExtractArchive(src, "zip", dest, Limits{}); err != nil {
			t.Fatalf("expected directory entry extraction to pass, got %v", err)
		}
	})

	t.Run("max files", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "many.zip")
		createZip(t, src, map[string]string{
			"a/SKILL.md":  "---\nname: a\ndescription: d\n---\n",
			"a/extra.txt": "x",
		})

		dest := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		err := ExtractArchive(src, "zip", dest, Limits{MaxFiles: 1, MaxTotalBytes: 1024, MaxFileBytes: 1024})
		if err == nil || !strings.Contains(err.Error(), "max files limit") {
			t.Fatalf("expected max-files error, got %v", err)
		}
	})

	t.Run("max file bytes", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "large.zip")
		createZip(t, src, map[string]string{
			"skill/SKILL.md": strings.Repeat("a", 50),
		})

		dest := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		err := ExtractArchive(src, "zip", dest, Limits{MaxFiles: 10, MaxTotalBytes: 1024, MaxFileBytes: 10})
		if err == nil || !strings.Contains(err.Error(), "max file bytes") {
			t.Fatalf("expected max-file-bytes error, got %v", err)
		}
	})

	t.Run("max total bytes", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "total.zip")
		createZip(t, src, map[string]string{
			"skill/SKILL.md": "12345",
			"skill/a.txt":    "12345",
		})

		dest := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		err := ExtractArchive(src, "zip", dest, Limits{MaxFiles: 10, MaxTotalBytes: 8, MaxFileBytes: 10})
		if err == nil || !strings.Contains(err.Error(), "max total bytes") {
			t.Fatalf("expected max-total-bytes error, got %v", err)
		}
	})

	t.Run("duplicate output path", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "dup.zip")
		createZipWithHeaders(t, src, []zipEntry{
			{name: "skill/SKILL.md", body: "a"},
			{name: "skill/SKILL.md", body: "b"},
		})

		dest := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		err := ExtractArchive(src, "zip", dest, Limits{MaxFiles: 10, MaxTotalBytes: 1024, MaxFileBytes: 1024})
		if err == nil || !strings.Contains(err.Error(), "failed to create output file") {
			t.Fatalf("expected duplicate-output error, got %v", err)
		}
	})
}

func TestExtractArchiveZipRejectsAbsolutePath(t *testing.T) {
	src := filepath.Join(t.TempDir(), "abs.zip")
	createZip(t, src, map[string]string{
		"/abs.txt": "bad",
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	err := ExtractArchive(src, "zip", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("expected absolute-path error, got %v", err)
	}
}

func TestExtractArchiveTarLimitsAndDuplicatePath(t *testing.T) {
	t.Run("max files", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "many.tar")
		createTar(t, src, []tarEntry{
			{name: "skill/SKILL.md", body: "x"},
			{name: "skill/a.txt", body: "y"},
		})

		dest := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		err := ExtractArchive(src, "tar", dest, Limits{MaxFiles: 1, MaxTotalBytes: 1024, MaxFileBytes: 1024})
		if err == nil || !strings.Contains(err.Error(), "max files limit") {
			t.Fatalf("expected max-files error, got %v", err)
		}
	})

	t.Run("max file bytes", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "large.tar")
		createTar(t, src, []tarEntry{
			{name: "skill/SKILL.md", body: strings.Repeat("a", 20)},
		})

		dest := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		err := ExtractArchive(src, "tar", dest, Limits{MaxFiles: 10, MaxTotalBytes: 1024, MaxFileBytes: 10})
		if err == nil || !strings.Contains(err.Error(), "max file bytes") {
			t.Fatalf("expected max-file-bytes error, got %v", err)
		}
	})

	t.Run("max total bytes", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "total.tar")
		createTar(t, src, []tarEntry{
			{name: "skill/SKILL.md", body: "12345"},
			{name: "skill/a.txt", body: "12345"},
		})

		dest := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		err := ExtractArchive(src, "tar", dest, Limits{MaxFiles: 10, MaxTotalBytes: 8, MaxFileBytes: 10})
		if err == nil || !strings.Contains(err.Error(), "max total bytes") {
			t.Fatalf("expected max-total-bytes error, got %v", err)
		}
	})

	t.Run("duplicate output path", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "dup.tar")
		createTar(t, src, []tarEntry{
			{name: "skill/SKILL.md", body: "a"},
			{name: "skill/SKILL.md", body: "b"},
		})

		dest := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		err := ExtractArchive(src, "tar", dest, Limits{MaxFiles: 10, MaxTotalBytes: 1024, MaxFileBytes: 1024})
		if err == nil || !strings.Contains(err.Error(), "failed to create output file") {
			t.Fatalf("expected duplicate-output error, got %v", err)
		}
	})

	t.Run("absolute path", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "abs.tar")
		createTar(t, src, []tarEntry{
			{name: "/abs.txt", body: "bad"},
		})

		dest := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		err := ExtractArchive(src, "tar", dest, Limits{})
		if err == nil || !strings.Contains(err.Error(), "absolute path") {
			t.Fatalf("expected absolute-path error, got %v", err)
		}
		if !strings.Contains(err.Error(), "ARCHIVE_PATH_ESCAPE") {
			t.Fatalf("expected ARCHIVE_PATH_ESCAPE marker, got %v", err)
		}
	})

	t.Run("backslash path escape", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "escape-backslash.tar")
		createTar(t, src, []tarEntry{
			{name: `..\evil.txt`, body: "bad"},
		})

		dest := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		err := ExtractArchive(src, "tar", dest, Limits{})
		if err == nil || !strings.Contains(err.Error(), "escapes destination") {
			t.Fatalf("expected backslash path-escape error, got %v", err)
		}
	})
}
