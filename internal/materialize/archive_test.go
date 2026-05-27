package materialize

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
