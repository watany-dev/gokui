package app

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestRoadmapRuleIDsAreImplemented(t *testing.T) {
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	rowPattern := regexp.MustCompile(`\| ` + "`" + `([A-Z0-9_]+)` + "`" + ` \|`)
	matches := rowPattern.FindAllStringSubmatch(roadmap, -1)
	if len(matches) == 0 {
		t.Fatal("ROADMAP.md rule table rows not found")
	}

	implFiles := []string{
		"../../internal/materialize/archive.go",
		"../../internal/app/app.go",
		"../../internal/skill/frontmatter.go",
	}
	var implText strings.Builder
	for _, dir := range []string{"../../internal/rule", "../../internal/scan"} {
		if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			implFiles = append(implFiles, path)
			return nil
		}); err != nil {
			t.Fatalf("failed to list implementation files in %s: %v", dir, err)
		}
	}
	sort.Strings(implFiles)
	for _, path := range implFiles {
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("failed to read implementation file %s: %v", path, readErr)
		}
		implText.WriteString(string(b))
		implText.WriteByte('\n')
	}
	impl := implText.String()

	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		id := m[1]
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if !strings.Contains(impl, `"`+id+`"`) {
			t.Fatalf("ROADMAP rule ID %q is not implemented in core sources", id)
		}
	}
}
