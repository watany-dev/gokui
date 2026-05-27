package scan

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAllScanFindingsUseRegistry(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	dir := filepath.Dir(file)
	literalFindingID := []byte(`ID:       "`)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read scan package dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if bytes.Contains(content, literalFindingID) {
			t.Fatalf("%s contains literal Finding rule ID; use newFinding(rule.X, ...) instead", name)
		}
	}
}
