package materialize

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/quick"

	"github.com/watany-dev/gokui/internal/limitio"
)

type archiveErrorStatter struct {
	err error
}

func (s archiveErrorStatter) Stat() (os.FileInfo, error) {
	return nil, s.err
}

func TestExtractArchiveZipSuccessAndDetectSkillRoot(t *testing.T) {
	src := filepath.Join(t.TempDir(), "skill.zip")
	createZip(t, src, map[string]string{
		"clean-skill/SKILL.md":  "---\nname: clean-skill\ndescription: Use when testing archive extraction.\n---\n",
		"clean-skill/README.md": "fixture",
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	if err := ExtractArchive(src, "zip", dest, Limits{}); err != nil {
		t.Fatalf("ExtractArchive(zip) error = %v", err)
	}

	root, err := DetectSkillRoot(dest)
	if err != nil {
		t.Fatalf("DetectSkillRoot() error = %v", err)
	}
	if filepath.Base(root) != "clean-skill" {
		t.Fatalf("skill root = %q, want clean-skill dir", root)
	}
}

func TestExtractArchiveZipRejectsPathEscape(t *testing.T) {
	src := filepath.Join(t.TempDir(), "escape.zip")
	createZip(t, src, map[string]string{
		"../evil.txt": "bad",
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	err := ExtractArchive(src, "zip", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "escapes destination") {
		t.Fatalf("expected path-escape error, got %v", err)
	}
	if !strings.Contains(err.Error(), "ARCHIVE_PATH_ESCAPE") {
		t.Fatalf("expected ARCHIVE_PATH_ESCAPE marker, got %v", err)
	}
}

func TestExtractArchiveZipRejectsBackslashPathEscape(t *testing.T) {
	src := filepath.Join(t.TempDir(), "escape-backslash.zip")
	createZip(t, src, map[string]string{
		`..\evil.txt`: "bad",
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	err := ExtractArchive(src, "zip", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "escapes destination") {
		t.Fatalf("expected backslash path-escape error, got %v", err)
	}
}

func TestExtractArchiveRejectsUnsupportedKind(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	err := ExtractArchive("ignored", "rar", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "unsupported archive kind") {
		t.Fatalf("expected unsupported kind error, got %v", err)
	}
}

func TestExtractArchiveOpenFailures(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	t.Run("zip open failure", func(t *testing.T) {
		err := ExtractArchive(filepath.Join(t.TempDir(), "missing.zip"), "zip", dest, Limits{})
		if err == nil || !strings.Contains(err.Error(), "failed to open zip archive") {
			t.Fatalf("expected zip-open error, got %v", err)
		}
	})

	t.Run("tar open failure", func(t *testing.T) {
		err := ExtractArchive(filepath.Join(t.TempDir(), "missing.tar"), "tar", dest, Limits{})
		if err == nil || !strings.Contains(err.Error(), "failed to open tar archive") {
			t.Fatalf("expected tar-open error, got %v", err)
		}
	})

	t.Run("zip parse failure", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "invalid.zip")
		if err := os.WriteFile(src, []byte("not-a-zip"), 0o644); err != nil {
			t.Fatalf("write invalid zip: %v", err)
		}
		err := ExtractArchive(src, "zip", dest, Limits{})
		if err == nil || !strings.Contains(err.Error(), "failed to open zip archive") {
			t.Fatalf("expected zip-parse error, got %v", err)
		}
	})

	t.Run("zip source must be regular file", func(t *testing.T) {
		srcDir := filepath.Join(t.TempDir(), "not-zip")
		if err := os.Mkdir(srcDir, 0o755); err != nil {
			t.Fatalf("mkdir source dir: %v", err)
		}
		err := ExtractArchive(srcDir, "zip", dest, Limits{})
		if err == nil || !strings.Contains(err.Error(), ruleArchiveSourceSpecialFile) {
			t.Fatalf("expected source-special-file error, got %v", err)
		}
	})

	t.Run("tar source must be regular file", func(t *testing.T) {
		srcDir := filepath.Join(t.TempDir(), "not-tar")
		if err := os.Mkdir(srcDir, 0o755); err != nil {
			t.Fatalf("mkdir source dir: %v", err)
		}
		err := ExtractArchive(srcDir, "tar", dest, Limits{})
		if err == nil || !strings.Contains(err.Error(), ruleArchiveSourceSpecialFile) {
			t.Fatalf("expected source-special-file error, got %v", err)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("zip source open denied", func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "blocked.zip")
			createZip(t, src, map[string]string{
				"SKILL.md": "---\nname: x\ndescription: d\n---\n",
			})
			if err := os.Chmod(src, 0o000); err != nil {
				t.Fatalf("chmod blocked zip: %v", err)
			}
			defer os.Chmod(src, 0o644)

			err := ExtractArchive(src, "zip", dest, Limits{})
			if err == nil || !strings.Contains(err.Error(), "failed to open zip archive") {
				t.Fatalf("expected zip-open denied error, got %v", err)
			}
		})

		t.Run("tar source open denied", func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "blocked.tar")
			createTar(t, src, []tarEntry{
				{name: "SKILL.md", body: "---\nname: x\ndescription: d\n---\n"},
			})
			if err := os.Chmod(src, 0o000); err != nil {
				t.Fatalf("chmod blocked tar: %v", err)
			}
			defer os.Chmod(src, 0o644)

			err := ExtractArchive(src, "tar", dest, Limits{})
			if err == nil || !strings.Contains(err.Error(), "failed to open tar archive") {
				t.Fatalf("expected tar-open denied error, got %v", err)
			}
		})

		t.Run("zip source symlink rejected", func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "skill.zip")
			createZip(t, target, map[string]string{
				"SKILL.md": "---\nname: x\ndescription: d\n---\n",
			})
			link := filepath.Join(dir, "skill-link.zip")
			if err := os.Symlink("skill.zip", link); err != nil {
				t.Fatalf("create zip symlink: %v", err)
			}
			err := ExtractArchive(link, "zip", dest, Limits{})
			if err == nil || !strings.Contains(err.Error(), ruleArchiveSourceSymlinkDetected) {
				t.Fatalf("expected source-symlink error, got %v", err)
			}
		})

		t.Run("tar source symlink rejected", func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "skill.tar")
			createTar(t, target, []tarEntry{
				{name: "SKILL.md", body: "---\nname: x\ndescription: d\n---\n"},
			})
			link := filepath.Join(dir, "skill-link.tar")
			if err := os.Symlink("skill.tar", link); err != nil {
				t.Fatalf("create tar symlink: %v", err)
			}
			err := ExtractArchive(link, "tar", dest, Limits{})
			if err == nil || !strings.Contains(err.Error(), ruleArchiveSourceSymlinkDetected) {
				t.Fatalf("expected source-symlink error, got %v", err)
			}
		})

		t.Run("zip source ancestor symlink rejected", func(t *testing.T) {
			base := t.TempDir()
			realParent := filepath.Join(base, "real-parent")
			if err := os.Mkdir(realParent, 0o755); err != nil {
				t.Fatalf("mkdir real parent: %v", err)
			}
			target := filepath.Join(realParent, "skill.zip")
			createZip(t, target, map[string]string{
				"SKILL.md": "---\nname: x\ndescription: d\n---\n",
			})
			linkParent := filepath.Join(base, "link-parent")
			if err := os.Symlink("real-parent", linkParent); err != nil {
				t.Fatalf("create parent symlink: %v", err)
			}
			err := ExtractArchive(filepath.Join(linkParent, "skill.zip"), "zip", dest, Limits{})
			if err == nil || !strings.Contains(err.Error(), ruleArchiveSourceSymlinkDetected) {
				t.Fatalf("expected source-ancestor-symlink error, got %v", err)
			}
		})

		t.Run("tar source ancestor symlink rejected", func(t *testing.T) {
			base := t.TempDir()
			realParent := filepath.Join(base, "real-parent")
			if err := os.Mkdir(realParent, 0o755); err != nil {
				t.Fatalf("mkdir real parent: %v", err)
			}
			target := filepath.Join(realParent, "skill.tar")
			createTar(t, target, []tarEntry{
				{name: "SKILL.md", body: "---\nname: x\ndescription: d\n---\n"},
			})
			linkParent := filepath.Join(base, "link-parent")
			if err := os.Symlink("real-parent", linkParent); err != nil {
				t.Fatalf("create parent symlink: %v", err)
			}
			err := ExtractArchive(filepath.Join(linkParent, "skill.tar"), "tar", dest, Limits{})
			if err == nil || !strings.Contains(err.Error(), ruleArchiveSourceSymlinkDetected) {
				t.Fatalf("expected source-ancestor-symlink error, got %v", err)
			}
		})
	}
}

func TestExtractArchiveTarGzSuccess(t *testing.T) {
	src := filepath.Join(t.TempDir(), "skill.tar.gz")
	createTarGz(t, src, []tarEntry{
		{name: "SKILL.md", body: "---\nname: root-skill\ndescription: Use when testing root tar extraction.\n---\n"},
		{name: "notes.txt", body: "fixture"},
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	if err := ExtractArchive(src, "tar", dest, Limits{}); err != nil {
		t.Fatalf("ExtractArchive(tar) error = %v", err)
	}

	root, err := DetectSkillRoot(dest)
	if err != nil {
		t.Fatalf("DetectSkillRoot() error = %v", err)
	}
	if root != dest {
		t.Fatalf("skill root = %q, want %q", root, dest)
	}
}

func TestExtractArchiveTarRejectsSymlink(t *testing.T) {
	src := filepath.Join(t.TempDir(), "symlink.tar")
	createTar(t, src, []tarEntry{
		{name: "SKILL.md", body: "---\nname: x\ndescription: d\n---\n"},
		{name: "link", typeflag: tar.TypeSymlink, linkname: "SKILL.md"},
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	err := ExtractArchive(src, "tar", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "symlink entry") {
		t.Fatalf("expected symlink error, got %v", err)
	}
	if !strings.Contains(err.Error(), "SYMLINK_IN_ARCHIVE") {
		t.Fatalf("expected SYMLINK_IN_ARCHIVE marker, got %v", err)
	}
}

func TestExtractArchiveTarRejectsHardlink(t *testing.T) {
	src := filepath.Join(t.TempDir(), "hardlink.tar")
	createTar(t, src, []tarEntry{
		{name: "SKILL.md", body: "---\nname: x\ndescription: d\n---\n"},
		{name: "hard", typeflag: tar.TypeLink, linkname: "SKILL.md"},
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	err := ExtractArchive(src, "tar", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "hardlink entry") {
		t.Fatalf("expected hardlink error, got %v", err)
	}
}

func TestExtractArchiveTarRejectsSpecialEntry(t *testing.T) {
	src := filepath.Join(t.TempDir(), "special.tar")
	createTar(t, src, []tarEntry{
		{name: "special", typeflag: tar.TypeChar},
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	err := ExtractArchive(src, "tar", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "unsupported special entry") {
		t.Fatalf("expected special-entry error, got %v", err)
	}
}

func TestExtractArchiveTarGzRejectsInvalidGzipStream(t *testing.T) {
	src := filepath.Join(t.TempDir(), "invalid.tar.gz")
	if err := os.WriteFile(src, []byte("not-gzip"), 0o644); err != nil {
		t.Fatalf("write invalid gzip: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	err := ExtractArchive(src, "tar", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "failed to open gzip stream") {
		t.Fatalf("expected gzip-open error, got %v", err)
	}
}

func TestExtractArchiveTarRejectsReadError(t *testing.T) {
	src := filepath.Join(t.TempDir(), "invalid.tar")
	if err := os.WriteFile(src, []byte("invalid tar"), 0o644); err != nil {
		t.Fatalf("write invalid tar: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	err := ExtractArchive(src, "tar", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "failed reading tar archive") {
		t.Fatalf("expected tar-read error, got %v", err)
	}
}

func TestExtractArchiveZipRejectsSymlinkEntry(t *testing.T) {
	src := filepath.Join(t.TempDir(), "symlink.zip")
	createZipWithHeaders(t, src, []zipEntry{
		{name: "SKILL.md", body: "---\nname: x\ndescription: d\n---\n"},
		{name: "link", body: "target", mode: os.ModeSymlink | 0o777},
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	err := ExtractArchive(src, "zip", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "symlink entry") {
		t.Fatalf("expected symlink error, got %v", err)
	}
	if !strings.Contains(err.Error(), "SYMLINK_IN_ARCHIVE") {
		t.Fatalf("expected SYMLINK_IN_ARCHIVE marker, got %v", err)
	}
}

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

func TestExtractArchiveRejectsNonEmptyDestination(t *testing.T) {
	src := filepath.Join(t.TempDir(), "skill.zip")
	createZip(t, src, map[string]string{
		"SKILL.md": "---\nname: x\ndescription: d\n---\n",
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "exists.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed destination: %v", err)
	}

	err := ExtractArchive(src, "zip", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("expected non-empty destination error, got %v", err)
	}
}

func TestExtractArchiveRejectsMissingOrFileDestination(t *testing.T) {
	src := filepath.Join(t.TempDir(), "skill.zip")
	createZip(t, src, map[string]string{
		"SKILL.md": "---\nname: x\ndescription: d\n---\n",
	})

	t.Run("missing destination", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "missing")
		err := ExtractArchive(src, "zip", dest, Limits{})
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected missing destination error, got %v", err)
		}
	})

	t.Run("destination is file", func(t *testing.T) {
		destFile := filepath.Join(t.TempDir(), "dest-file")
		if err := os.WriteFile(destFile, []byte("x"), 0o644); err != nil {
			t.Fatalf("write dest file: %v", err)
		}
		err := ExtractArchive(src, "zip", destFile, Limits{})
		if err == nil || !strings.Contains(err.Error(), "must be a directory") {
			t.Fatalf("expected file-destination error, got %v", err)
		}
	})
}

func TestEnsureEmptyDirReadFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission model differs on windows")
	}

	parent := t.TempDir()
	locked := filepath.Join(parent, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod locked: %v", err)
	}
	defer os.Chmod(locked, 0o755)

	err := ensureEmptyDir(locked)
	if err == nil || !strings.Contains(err.Error(), "failed to read destination directory") {
		t.Fatalf("expected readdir error, got %v", err)
	}
}

func TestDetectSkillRootRejectsAmbiguousLayout(t *testing.T) {
	t.Run("multiple top-level directories", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "a"), 0o755); err != nil {
			t.Fatalf("mkdir a: %v", err)
		}
		if err := os.Mkdir(filepath.Join(dir, "b"), 0o755); err != nil {
			t.Fatalf("mkdir b: %v", err)
		}

		_, err := DetectSkillRoot(dir)
		if err == nil || !strings.Contains(err.Error(), "single top-level directory") {
			t.Fatalf("expected ambiguous layout error, got %v", err)
		}
	})

	t.Run("single top-level directory with extra top-level file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "skill"), 0o755); err != nil {
			t.Fatalf("mkdir skill: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "skill", "SKILL.md"), []byte("---\nname: skill\ndescription: d\n---\n"), 0o644); err != nil {
			t.Fatalf("write SKILL.md: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("extra"), 0o644); err != nil {
			t.Fatalf("write README.md: %v", err)
		}

		_, err := DetectSkillRoot(dir)
		if err == nil || !strings.Contains(err.Error(), "single top-level directory") {
			t.Fatalf("expected extra-top-level-file rejection, got %v", err)
		}
	})
}

func TestDetectSkillRootErrorCases(t *testing.T) {
	t.Run("missing extracted directory", func(t *testing.T) {
		_, err := DetectSkillRoot(filepath.Join(t.TempDir(), "missing"))
		if err == nil || !strings.Contains(err.Error(), "failed to read extracted archive") {
			t.Fatalf("expected read-dir error, got %v", err)
		}
	})

	t.Run("single top-level directory without SKILL", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "one"), 0o755); err != nil {
			t.Fatalf("mkdir one: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "one", "README.md"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write readme: %v", err)
		}

		_, err := DetectSkillRoot(dir)
		if err == nil || !strings.Contains(err.Error(), "single top-level directory") {
			t.Fatalf("expected missing-skill error, got %v", err)
		}
	})
}

func TestSafeJoinRejectsAbsoluteAndDot(t *testing.T) {
	root := t.TempDir()

	_, err := safeJoin(root, filepath.Join(string(filepath.Separator), "abs", "x"))
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("expected absolute-path error, got %v", err)
	}

	_, err = safeJoin(root, ".")
	if err == nil || !strings.Contains(err.Error(), "invalid path") {
		t.Fatalf("expected invalid-path error, got %v", err)
	}

	_, err = safeJoin(root, "C:/Windows/System32/drivers/etc/hosts")
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("expected windows-drive absolute-path error, got %v", err)
	}

	_, err = safeJoin(root, "safe/../C:/Windows/System32/drivers/etc/hosts")
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("expected normalized windows-drive absolute-path error, got %v", err)
	}

	invalidName := string([]byte{'b', 0xff, 'a'})
	_, err = safeJoin(root, invalidName)
	if err == nil || !strings.Contains(err.Error(), ruleArchivePathInvalidUTF8) {
		t.Fatalf("expected invalid utf-8 archive path error, got %v", err)
	}
}

func TestSafeJoinPropertyNoEscapeNoPanic(t *testing.T) {
	root := t.TempDir()
	prop := func(name string) (ok bool) {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()

		joined, err := safeJoin(root, name)
		if err != nil {
			return true
		}
		rel, relErr := filepath.Rel(root, joined)
		if relErr != nil {
			return false
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatalf("safeJoin property failed: %v", err)
	}
}

func TestSafeJoinPropertyRejectsParentTraversal(t *testing.T) {
	root := t.TempDir()
	prop := func(depth uint8) bool {
		name := strings.Repeat("../", int(depth)+1) + "escape.txt"
		_, err := safeJoin(root, name)
		return err != nil
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("safeJoin traversal-rejection property failed: %v", err)
	}
}

func TestEnsureArchiveSourceStableFromOpen(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.zip")
	secondPath := filepath.Join(dir, "second.zip")
	if err := os.WriteFile(firstPath, []byte("first"), 0o644); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := os.WriteFile(secondPath, []byte("second"), 0o644); err != nil {
		t.Fatalf("write second: %v", err)
	}

	firstInfo, err := os.Lstat(firstPath)
	if err != nil {
		t.Fatalf("lstat first: %v", err)
	}
	if err := ensureArchiveSourceStableFromOpen(firstInfo, archiveErrorStatter{err: errors.New("stat fail")}, firstPath); err == nil || !strings.Contains(err.Error(), "failed to open archive source") {
		t.Fatalf("expected archive source stat failure, got %v", err)
	}

	firstOpened, err := os.Open(firstPath)
	if err != nil {
		t.Fatalf("open first: %v", err)
	}
	defer firstOpened.Close()
	if err := ensureArchiveSourceStableFromOpen(firstInfo, firstOpened, firstPath); err != nil {
		t.Fatalf("same archive source identity should pass, got %v", err)
	}

	secondOpened, err := os.Open(secondPath)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	defer secondOpened.Close()
	if err := ensureArchiveSourceStableFromOpen(firstInfo, secondOpened, secondPath); err == nil || !strings.Contains(err.Error(), ruleArchiveSourceChanged) {
		t.Fatalf("expected source-changed archive error, got %v", err)
	}
}

func TestRejectArchiveSourceSymlinkPathGuards(t *testing.T) {
	t.Run("allows missing path", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "missing.zip")
		if err := rejectArchiveSourceSymlinkPath(src); err != nil {
			t.Fatalf("missing path should not fail symlink guard, got %v", err)
		}
	})

	t.Run("allows ENOTDIR segment", func(t *testing.T) {
		base := t.TempDir()
		nonDir := filepath.Join(base, "not-dir")
		if err := os.WriteFile(nonDir, []byte("x"), 0o644); err != nil {
			t.Fatalf("write non-dir segment: %v", err)
		}
		src := filepath.Join(nonDir, "nested.zip")
		if err := rejectArchiveSourceSymlinkPath(src); err != nil {
			t.Fatalf("ENOTDIR path should not fail symlink guard, got %v", err)
		}
	})

	t.Run("invalid path reports evaluation failure", func(t *testing.T) {
		err := rejectArchiveSourceSymlinkPath("\x00")
		if err == nil || !strings.Contains(err.Error(), "failed to evaluate archive source path") {
			t.Fatalf("expected archive-source path evaluation failure, got %v", err)
		}
	})
}

func TestIsRootLevelPathComponent(t *testing.T) {
	if isRootLevelPathComponent("relative/path") {
		t.Fatal("relative path must not be treated as root-level component")
	}
	if isRootLevelPathComponent(string(os.PathSeparator)) {
		t.Fatal("filesystem root must not be treated as root-level component")
	}
	rootChild := rootChildPathForTest(t)
	if !isRootLevelPathComponent(rootChild) {
		t.Fatalf("expected root child to be treated as root-level component: %q", rootChild)
	}
	deeper := filepath.Join(rootChild, "tmp")
	if isRootLevelPathComponent(deeper) {
		t.Fatalf("deeper path must not be treated as root-level component: %q", deeper)
	}
}

func TestRejectArchiveSourceSymlinkPathAllowsRootLevelSymlinkComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("absolute root-level symlink layout differs on windows")
	}

	info, err := os.Lstat("/bin")
	if err != nil {
		t.Skipf("skip: lstat /bin failed: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Skip("/bin is not a symlink on this environment")
	}

	src := filepath.Join("/bin", "gokui-root-level-symlink-guard-test.tar")
	if err := rejectArchiveSourceSymlinkPath(src); err != nil {
		t.Fatalf("expected root-level symlink component to be allowed, got %v", err)
	}
}

func rootChildPathForTest(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return filepath.Join(string(os.PathSeparator), "var")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Skipf("skip: getwd failed on windows: %v", err)
	}
	vol := filepath.VolumeName(cwd)
	if vol == "" {
		t.Skip("skip: windows volume name unavailable")
	}
	return filepath.Join(vol+string(os.PathSeparator), "var")
}

func TestWriteZipAndTarFileLimits(t *testing.T) {
	t.Run("writeZipFile read failure from corrupted payload", func(t *testing.T) {
		zipPath := filepath.Join(t.TempDir(), "corrupt.zip")
		createZip(t, zipPath, map[string]string{
			"SKILL.md": strings.Repeat("abcd", 100),
		})

		reader, err := zip.OpenReader(zipPath)
		if err != nil {
			t.Fatalf("open reader: %v", err)
		}
		offset, err := reader.File[0].DataOffset()
		reader.Close()
		if err != nil {
			t.Fatalf("data offset: %v", err)
		}

		file, err := os.OpenFile(zipPath, os.O_WRONLY, 0)
		if err != nil {
			t.Fatalf("open zip for corruption: %v", err)
		}
		if _, err := file.WriteAt([]byte{0x00, 0x00, 0x00, 0x00}, offset+4); err != nil {
			file.Close()
			t.Fatalf("corrupt payload: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close corrupted zip: %v", err)
		}

		reader, err = zip.OpenReader(zipPath)
		if err != nil {
			t.Fatalf("reopen reader: %v", err)
		}
		defer reader.Close()

		out := filepath.Join(t.TempDir(), "SKILL.md")
		_, err = writeZipFile(reader.File[0], out, 1<<20)
		if err == nil || !strings.Contains(err.Error(), "failed to extract file") {
			t.Fatalf("expected extract error, got %v", err)
		}
	})

	t.Run("writeZipFile exceeds max during extraction", func(t *testing.T) {
		zipPath := filepath.Join(t.TempDir(), "sample.zip")
		createZip(t, zipPath, map[string]string{
			"SKILL.md": "12345",
		})

		reader, err := zip.OpenReader(zipPath)
		if err != nil {
			t.Fatalf("open reader: %v", err)
		}
		defer reader.Close()

		out := filepath.Join(t.TempDir(), "SKILL.md")
		_, err = writeZipFile(reader.File[0], out, 2)
		if err == nil || !strings.Contains(err.Error(), "max file bytes during extraction") {
			t.Fatalf("expected zip max-bytes error, got %v", err)
		}
		info, statErr := os.Stat(out)
		if statErr == nil {
			t.Fatalf("oversized output file should be removed, got size=%d path=%s", info.Size(), out)
		}
		if !os.IsNotExist(statErr) {
			t.Fatalf("expected not-exist after oversized extraction error, statErr=%v", statErr)
		}
	})

	t.Run("writeTarFile exceeds max during extraction", func(t *testing.T) {
		header := &tar.Header{Name: "SKILL.md"}
		out := filepath.Join(t.TempDir(), "SKILL.md")
		reader := tar.NewReader(singleFileTarReader(t, "SKILL.md", "12345"))
		if _, err := reader.Next(); err != nil {
			t.Fatalf("read tar header: %v", err)
		}

		_, err := writeTarFile(header, reader, out, 2)
		if err == nil || !strings.Contains(err.Error(), "max file bytes during extraction") {
			t.Fatalf("expected tar max-bytes error, got %v", err)
		}
		info, statErr := os.Stat(out)
		if statErr == nil {
			t.Fatalf("oversized output file should be removed, got size=%d path=%s", info.Size(), out)
		}
		if !os.IsNotExist(statErr) {
			t.Fatalf("expected not-exist after oversized extraction error, statErr=%v", statErr)
		}
	})

	t.Run("writeTarFile output create failure", func(t *testing.T) {
		header := &tar.Header{Name: "SKILL.md"}
		dir := filepath.Join(t.TempDir(), "existing-dir")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		reader := tar.NewReader(singleFileTarReader(t, "SKILL.md", "x"))
		if _, err := reader.Next(); err != nil {
			t.Fatalf("read tar header: %v", err)
		}

		_, err := writeTarFile(header, reader, dir, 10)
		if err == nil || !strings.Contains(err.Error(), "failed to create output file") {
			t.Fatalf("expected output-create error, got %v", err)
		}
	})

	t.Run("writeTarFile read failure", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		header := &tar.Header{
			Name:     "SKILL.md",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     10,
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte("0123456789")); err != nil {
			t.Fatalf("write body: %v", err)
		}
		if err := tw.Close(); err != nil {
			t.Fatalf("close writer: %v", err)
		}

		raw := buf.Bytes()
		truncated := raw[:512+5]
		reader := tar.NewReader(bytes.NewReader(truncated))
		gotHeader, err := reader.Next()
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		out := filepath.Join(t.TempDir(), "SKILL.md")
		_, err = writeTarFile(gotHeader, reader, out, 1<<20)
		if err == nil || !strings.Contains(err.Error(), "failed to extract file") {
			t.Fatalf("expected tar read error, got %v", err)
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

type tarEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

type zipEntry struct {
	name string
	body string
	mode os.FileMode
}

func createZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
}

func createZipWithHeaders(t *testing.T, path string, files []zipEntry) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	for _, file := range files {
		header := &zip.FileHeader{Name: file.name, Method: zip.Deflate}
		if file.mode != 0 {
			header.SetMode(file.mode)
		}
		w, err := zw.CreateHeader(header)
		if err != nil {
			t.Fatalf("zip create %s: %v", file.name, err)
		}
		if _, err := w.Write([]byte(file.body)); err != nil {
			t.Fatalf("zip write %s: %v", file.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
}

func createTar(t *testing.T, path string, entries []tarEntry) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tar: %v", err)
	}
	defer out.Close()

	tw := tar.NewWriter(out)
	defer tw.Close()

	writeTarEntries(t, tw, entries)
}

func createTarGz(t *testing.T, path string, entries []tarEntry) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tar.gz: %v", err)
	}
	defer out.Close()

	gzw := gzip.NewWriter(out)
	tw := tar.NewWriter(gzw)
	writeTarEntries(t, tw, entries)

	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
}

func writeTarEntries(t *testing.T, tw *tar.Writer, entries []tarEntry) {
	t.Helper()
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}

		header := &tar.Header{
			Name:     entry.name,
			Typeflag: typeflag,
			Mode:     0o644,
			Linkname: entry.linkname,
		}
		body := []byte(entry.body)
		if typeflag == tar.TypeReg {
			header.Size = int64(len(body))
		}

		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write tar header %s: %v", entry.name, err)
		}
		if header.Size > 0 {
			if _, err := bytes.NewReader(body).WriteTo(tw); err != nil {
				t.Fatalf("write tar body %s: %v", entry.name, err)
			}
		}
	}
}

func singleFileTarReader(t *testing.T, name string, body string) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	header := &tar.Header{
		Name:     name,
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(body)),
	}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}
