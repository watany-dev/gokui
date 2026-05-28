package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanSkillRootScansDependencyManifestFiles(t *testing.T) {
	root := t.TempDir()
	packageManifest := `{
  "name": "demo",
  "scripts": {
    "setup": "npx tool"
  }
}`
	denoManifest := `{
  // jsonc comment is common in deno config files
  "tasks": {
    "setup": "deno run -A npm:create-next-app@latest"
  }
}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(packageManifest), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "deno.jsonc"), []byte(denoManifest), 0o644); err != nil {
		t.Fatalf("write deno.jsonc: %v", err)
	}

	findings, err := ScanSkillRoot(root)
	if err != nil {
		t.Fatalf("ScanSkillRoot() error = %v", err)
	}
	seenPackageRuntime := false
	seenDenoRuntime := false
	for _, finding := range findings {
		if finding.File == "package.json" && finding.ID == "UNKNOWN_FILE_TYPE" {
			t.Fatalf("package.json should be scanned as known manifest, got UNKNOWN_FILE_TYPE finding: %+v", finding)
		}
		if finding.File == "deno.jsonc" && finding.ID == "UNKNOWN_FILE_TYPE" {
			t.Fatalf("deno.jsonc should be scanned as known manifest, got UNKNOWN_FILE_TYPE finding: %+v", finding)
		}
		if finding.File == "package.json" && finding.ID == "UNPINNED_RUNTIME_TOOL" {
			seenPackageRuntime = true
		}
		if finding.File == "deno.jsonc" && finding.ID == "UNPINNED_RUNTIME_TOOL" {
			seenDenoRuntime = true
		}
	}
	if !seenPackageRuntime {
		t.Fatal("expected UNPINNED_RUNTIME_TOOL finding in package.json")
	}
	if !seenDenoRuntime {
		t.Fatal("expected UNPINNED_RUNTIME_TOOL finding in deno.jsonc")
	}
}
