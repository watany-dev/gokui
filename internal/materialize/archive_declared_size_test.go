package materialize

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractArchiveZipDeclaredSizeCapsTotalQuota(t *testing.T) {
	src := filepath.Join(t.TempDir(), "quota.zip")
	createZipWithDeclaredUncompressedSize(t, src, []zipDeclaredEntry{
		{name: "skill/a.txt", body: "aaaa", declaredUncompressed: 1},
		{name: "skill/b.txt", body: "bbbb", declaredUncompressed: 1},
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	err := ExtractArchive(src, "zip", dest, Limits{MaxFiles: 10, MaxTotalBytes: 3, MaxFileBytes: 100})
	if err == nil || !strings.Contains(err.Error(), "max total bytes") {
		t.Fatalf("expected max-total-bytes error, got %v", err)
	}
}

type zipDeclaredEntry struct {
	name                 string
	body                 string
	declaredUncompressed uint64
}

func createZipWithDeclaredUncompressedSize(t *testing.T, path string, files []zipDeclaredEntry) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	for _, file := range files {
		header := &zip.FileHeader{
			Name:   file.name,
			Method: zip.Store,
		}
		header.UncompressedSize64 = file.declaredUncompressed
		header.CompressedSize64 = uint64(len(file.body))
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
