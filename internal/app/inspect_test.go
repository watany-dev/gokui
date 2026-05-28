package app

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	reportpkg "github.com/watany-dev/gokui/internal/report"
	skillpkg "github.com/watany-dev/gokui/internal/skill"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseInspectArgs(t *testing.T) {
	t.Run("parses source and default format", func(t *testing.T) {
		input, format, err := parseInspectArgs([]string{"./skill"})
		if err != nil {
			t.Fatalf("parseInspectArgs() error = %v", err)
		}
		if input != "./skill" {
			t.Fatalf("input = %q, want %q", input, "./skill")
		}
		if format != "human" {
			t.Fatalf("format = %q, want %q", format, "human")
		}
	})

	t.Run("parses equals format", func(t *testing.T) {
		input, format, err := parseInspectArgs([]string{"./skill", "--format=json"})
		if err != nil {
			t.Fatalf("parseInspectArgs() error = %v", err)
		}
		if input != "./skill" || format != "json" {
			t.Fatalf("got (%q, %q), want (%q, %q)", input, format, "./skill", "json")
		}
	})

	t.Run("parses sarif format", func(t *testing.T) {
		input, format, err := parseInspectArgs([]string{"./skill", "--format", "sarif"})
		if err != nil {
			t.Fatalf("parseInspectArgs() error = %v", err)
		}
		if input != "./skill" || format != "sarif" {
			t.Fatalf("got (%q, %q), want (%q, %q)", input, format, "./skill", "sarif")
		}
	})

	t.Run("parses compact format", func(t *testing.T) {
		input, format, err := parseInspectArgs([]string{"./skill", "--format", "compact"})
		if err != nil {
			t.Fatalf("parseInspectArgs() error = %v", err)
		}
		if input != "./skill" || format != "compact" {
			t.Fatalf("got (%q, %q), want (%q, %q)", input, format, "./skill", "compact")
		}
	})

	t.Run("parses review-json format", func(t *testing.T) {
		input, format, err := parseInspectArgs([]string{"./skill", "--format", "review-json"})
		if err != nil {
			t.Fatalf("parseInspectArgs() error = %v", err)
		}
		if input != "./skill" || format != "review-json" {
			t.Fatalf("got (%q, %q), want (%q, %q)", input, format, "./skill", "review-json")
		}
	})

	t.Run("errors when format value is missing", func(t *testing.T) {
		_, _, err := parseInspectArgs([]string{"./skill", "--format"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --format") {
			t.Fatalf("expected missing format error, got %v", err)
		}
	})

	t.Run("errors when more than one source is given", func(t *testing.T) {
		_, _, err := parseInspectArgs([]string{"./a", "./b"})
		if err == nil || !strings.Contains(err.Error(), "inspect accepts exactly one source") {
			t.Fatalf("expected single source error, got %v", err)
		}
	})
}

func TestParseVetArgs(t *testing.T) {
	t.Run("parses source and default format", func(t *testing.T) {
		input, format, profile, profileSet, err := parseVetArgs([]string{"./skill"})
		if err != nil {
			t.Fatalf("parseVetArgs() error = %v", err)
		}
		if input != "./skill" {
			t.Fatalf("input = %q, want %q", input, "./skill")
		}
		if format != "human" {
			t.Fatalf("format = %q, want %q", format, "human")
		}
		if profile != policypkg.ProfileStrict.String() || profileSet {
			t.Fatalf("profile/profileSet = %q/%t, want %q/false", profile, profileSet, policypkg.ProfileStrict.String())
		}
	})

	t.Run("parses equals format", func(t *testing.T) {
		input, format, _, _, err := parseVetArgs([]string{"./skill", "--format=json"})
		if err != nil {
			t.Fatalf("parseVetArgs() error = %v", err)
		}
		if input != "./skill" || format != "json" {
			t.Fatalf("got (%q, %q), want (%q, %q)", input, format, "./skill", "json")
		}
	})

	t.Run("parses sarif format", func(t *testing.T) {
		input, format, _, _, err := parseVetArgs([]string{"./skill", "--format", "sarif"})
		if err != nil {
			t.Fatalf("parseVetArgs() error = %v", err)
		}
		if input != "./skill" || format != "sarif" {
			t.Fatalf("got (%q, %q), want (%q, %q)", input, format, "./skill", "sarif")
		}
	})

	t.Run("parses compact format", func(t *testing.T) {
		input, format, _, _, err := parseVetArgs([]string{"./skill", "--format", "compact"})
		if err != nil {
			t.Fatalf("parseVetArgs() error = %v", err)
		}
		if input != "./skill" || format != "compact" {
			t.Fatalf("got (%q, %q), want (%q, %q)", input, format, "./skill", "compact")
		}
	})

	t.Run("parses review-json format", func(t *testing.T) {
		input, format, _, _, err := parseVetArgs([]string{"./skill", "--format", "review-json"})
		if err != nil {
			t.Fatalf("parseVetArgs() error = %v", err)
		}
		if input != "./skill" || format != "review-json" {
			t.Fatalf("got (%q, %q), want (%q, %q)", input, format, "./skill", "review-json")
		}
	})

	t.Run("parses profile options", func(t *testing.T) {
		_, _, profile, profileSet, err := parseVetArgs([]string{"./skill", "--profile", "research"})
		if err != nil {
			t.Fatalf("parseVetArgs() error = %v", err)
		}
		if profile != "research" || !profileSet {
			t.Fatalf("profile/profileSet = %q/%t, want research/true", profile, profileSet)
		}
		_, _, profile, profileSet, err = parseVetArgs([]string{"./skill", "--profile=team"})
		if err != nil {
			t.Fatalf("parseVetArgs() equals profile error = %v", err)
		}
		if profile != "team" || !profileSet {
			t.Fatalf("profile/profileSet (equals) = %q/%t, want team/true", profile, profileSet)
		}
	})

	t.Run("errors when source is missing", func(t *testing.T) {
		_, _, _, _, err := parseVetArgs([]string{"--format", "json"})
		if err == nil || !strings.Contains(err.Error(), "vet source is required") {
			t.Fatalf("expected source required error, got %v", err)
		}
	})

	t.Run("errors when format value is missing", func(t *testing.T) {
		_, _, _, _, err := parseVetArgs([]string{"./skill", "--format"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --format") {
			t.Fatalf("expected missing format error, got %v", err)
		}
	})

	t.Run("errors when profile value is missing", func(t *testing.T) {
		_, _, _, _, err := parseVetArgs([]string{"./skill", "--profile"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --profile") {
			t.Fatalf("expected missing profile error, got %v", err)
		}
	})

	t.Run("errors on unknown option", func(t *testing.T) {
		_, _, _, _, err := parseVetArgs([]string{"./skill", "--badopt"})
		if err == nil || !strings.Contains(err.Error(), "unknown vet option") {
			t.Fatalf("expected unknown option error, got %v", err)
		}
	})

	t.Run("errors on multiple sources", func(t *testing.T) {
		_, _, _, _, err := parseVetArgs([]string{"./a", "./b"})
		if err == nil || !strings.Contains(err.Error(), "vet accepts exactly one source") {
			t.Fatalf("expected single source error, got %v", err)
		}
	})

	t.Run("errors on unsupported format", func(t *testing.T) {
		_, _, _, _, err := parseVetArgs([]string{"./skill", "--format", "xml"})
		if err == nil || !strings.Contains(err.Error(), "unsupported vet format") {
			t.Fatalf("expected unsupported format error, got %v", err)
		}
	})
}

func TestInspectArgJSONHelpers(t *testing.T) {
	if !argsRequestFormat([]string{"./skill", "--format", "json"}, "json") {
		t.Fatal("argsRequestFormat json should detect --format json")
	}
	if !argsRequestFormat([]string{"./skill", "--format=json"}, "json") {
		t.Fatal("argsRequestFormat json should detect --format=json")
	}
	if argsRequestFormat([]string{"./skill", "--format", "human"}, "json") {
		t.Fatal("argsRequestFormat json should be false for non-json format")
	}
	if !argsRequestFormat([]string{"./skill", "--format", "sarif"}, "sarif") {
		t.Fatal("argsRequestFormat sarif should detect --format sarif")
	}
	if !argsRequestFormat([]string{"./skill", "--format=sarif"}, "sarif") {
		t.Fatal("argsRequestFormat sarif should detect --format=sarif")
	}
	if argsRequestFormat([]string{"./skill", "--format", "human"}, "sarif") {
		t.Fatal("argsRequestFormat sarif should be false for non-sarif format")
	}
	if !argsRequestFormat([]string{"./skill", "--format", "review-json"}, "review-json") {
		t.Fatal("argsRequestFormat review-json should detect --format review-json")
	}
	if !argsRequestFormat([]string{"./skill", "--format=review-json"}, "review-json") {
		t.Fatal("argsRequestFormat review-json should detect --format=review-json")
	}
	if argsRequestFormat([]string{"./skill", "--format", "human"}, "review-json") {
		t.Fatal("argsRequestFormat review-json should be false for non-review format")
	}

	if got := extractInspectSourceArg([]string{"./skill", "--format", "json"}); got != "./skill" {
		t.Fatalf("extractInspectSourceArg() = %q, want %q", got, "./skill")
	}
	if got := extractInspectSourceArg([]string{"--format=json", "./skill"}); got != "./skill" {
		t.Fatalf("extractInspectSourceArg() with equals = %q, want %q", got, "./skill")
	}
	if got := extractInspectSourceArg([]string{"--format", "json"}); got != "" {
		t.Fatalf("extractInspectSourceArg() without source = %q, want empty", got)
	}
	if got := extractInspectSourceArg([]string{"--unknown", "./skill", "--format", "json"}); got != "./skill" {
		t.Fatalf("extractInspectSourceArg() should skip unknown options, got %q", got)
	}
}

func TestBuildInspectReviewReportNeutralizesText(t *testing.T) {
	report := inspectReport{
		SchemaVersion: reportSchemaVersion,
		PreRelease:    true,
		Source: source{
			Input: "github:org/repo//skills/x@\u202Etag",
			Kind:  "github-source",
		},
		Decision: "REJECTED",
		Findings: []inspectFinding{
			{
				ID:       "PROMPT_OVERRIDE_LANGUAGE",
				Severity: "high",
				File:     "SKILL.md",
				Line:     10,
				Summary:  "line1\nline2 \u202E hidden",
			},
			{
				ID:       "RAW_HTML_MARKUP",
				Severity: "medium",
				File:     "README.md",
				Line:     3,
				Summary:  "<script>alert(1)</script>",
			},
			{
				ID:       "NFKC_CHANGES_TEXT",
				Severity: "low",
				File:     "notes.md",
				Line:     8,
				Summary:  "compatibility normalization changed text",
			},
		},
		Note: "review export",
	}
	review := buildInspectReviewReport(report)
	if !review.Neutralized {
		t.Fatal("review report should be marked neutralized")
	}
	if review.Summary.Total != 3 || review.Summary.High != 1 || review.Summary.Medium != 1 || review.Summary.Low != 1 {
		t.Fatalf("unexpected review summary: %+v", review.Summary)
	}
	if len(review.Findings) != 3 {
		t.Fatalf("findings len = %d, want 3", len(review.Findings))
	}
	if !strings.Contains(review.Findings[0].SummaryNeutralized, "\\n") {
		t.Fatalf("summary should be escaped, got %q", review.Findings[0].SummaryNeutralized)
	}
	if strings.ContainsRune(review.Findings[0].SummaryNeutralized, '\u202E') {
		t.Fatalf("summary should not contain raw bidi char, got %q", review.Findings[0].SummaryNeutralized)
	}
	if strings.ContainsRune(review.Source.Input, '\u202E') {
		t.Fatalf("source input should be neutralized, got %q", review.Source.Input)
	}
}

func TestDetectSourceKind(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "github:org/repo//skills/x@abc123", want: "github-source"},
		{in: "./skill.zip", want: "zip"},
		{in: "./skill.tgz", want: "tar"},
		{in: "./skill.tar.gz", want: "tar"},
		{in: "./skill", want: "local-dir"},
	}

	for _, tc := range cases {
		if got := detectSourceKind(tc.in); got != tc.want {
			t.Fatalf("detectSourceKind(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBuildInspectSARIFReport(t *testing.T) {
	report := inspectReport{
		SchemaVersion: reportSchemaVersion,
		PreRelease:    true,
		Source: source{
			Input: "./fixture-skill",
			Kind:  "local-dir",
		},
		Decision: "REJECTED",
		Note:     "test note",
		Findings: []inspectFinding{
			{
				ID:       "Z_RULE",
				Severity: "medium",
				File:     "SKILL.md",
				Line:     7,
				Summary:  "medium severity finding",
			},
			{
				ID:       "A_RULE",
				Severity: "critical",
				File:     "refs/guide.md",
				Line:     2,
				Summary:  "critical severity finding",
			},
			{
				ID:       "A_RULE",
				Severity: "low",
				File:     "",
				Line:     0,
				Summary:  "duplicate rule id should not duplicate rules",
			},
		},
	}

	got := buildInspectSARIFReport(report)
	if got.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", got.Version)
	}
	if len(got.Runs) != 1 {
		t.Fatalf("runs length = %d, want 1", len(got.Runs))
	}
	run := got.Runs[0]
	if run.Properties.Decision != "REJECTED" {
		t.Fatalf("properties.decision = %q, want REJECTED", run.Properties.Decision)
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("executionSuccessful should be false for rejected decision, got %+v", run.Invocations)
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules length = %d, want 2 (deduplicated)", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "A_RULE" || run.Tool.Driver.Rules[1].ID != "Z_RULE" {
		t.Fatalf("rules should be sorted by id, got %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results length = %d, want 3", len(run.Results))
	}
	if run.Results[0].Level != "warning" {
		t.Fatalf("first result level = %q, want warning", run.Results[0].Level)
	}
	if len(run.Results[0].Locations) != 1 {
		t.Fatalf("first result should include one location, got %d", len(run.Results[0].Locations))
	}
	if run.Results[0].Locations[0].PhysicalLocation.Region == nil || run.Results[0].Locations[0].PhysicalLocation.Region.StartLine != 7 {
		t.Fatalf("first result should include start line 7, got %+v", run.Results[0].Locations[0].PhysicalLocation.Region)
	}
	if run.Results[2].Level != "note" {
		t.Fatalf("third result level = %q, want note", run.Results[2].Level)
	}
	if len(run.Results[2].Locations) != 0 {
		t.Fatalf("result without file should not include locations, got %+v", run.Results[2].Locations)
	}
}

func TestBuildInspectSARIFErrorReport(t *testing.T) {
	report := inspectErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     inspectErrorCodeSourceNotFound,
		Message:       "inspect source not found: /tmp/missing",
		Source: source{
			Input: "/tmp/missing",
			Kind:  "local-dir",
		},
		Note: "inspect source must exist before validation",
	}
	sarif := buildInspectSARIFErrorReport(report)
	if sarif.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs length = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("results length = %d, want 1", len(run.Results))
	}
	if run.Results[0].RuleID != inspectErrorCodeSourceNotFound {
		t.Fatalf("rule id = %q, want %q", run.Results[0].RuleID, inspectErrorCodeSourceNotFound)
	}
	if run.Results[0].Level != "error" {
		t.Fatalf("level = %q, want error", run.Results[0].Level)
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("invocation should be unsuccessful, got %+v", run.Invocations)
	}
}

func TestEmitInspectStructuredErrorReviewJSON(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	ok := emitInspectStructuredError("review-json", &stdout, &stderr, inspectErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     inspectErrorCodeArgsInvalid,
		Message:       "inspect source is required",
		Source: source{
			Input: "",
			Kind:  "local-dir",
		},
		Note: "inspect failed before source evaluation",
	})
	if !ok {
		t.Fatal("emitInspectStructuredError(review-json) should return true")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for structured review-json error, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeArgsInvalid+"\"") {
		t.Fatalf("stdout should include inspect error code, got %q", stdout.String())
	}
}

func TestWriteInspectSARIFErrorPreservesExplicitRuleID(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := writeInspectSARIFError(&stdout, &stderr, inspectErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     inspectErrorCodeScanFailed,
		RuleID:        "EXPLICIT_RULE",
		Message:       "EXPLICIT_RULE: synthetic inspect error",
		Source: source{
			Input: "./skill",
			Kind:  "local-dir",
		},
		Note: "test",
	})
	if code != 1 {
		t.Fatalf("writeInspectSARIFError() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	var sarif reportpkg.SARIFDocument
	if err := json.Unmarshal(stdout.Bytes(), &sarif); err != nil {
		t.Fatalf("sarif parse failed: %v", err)
	}
	if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("unexpected sarif structure: %+v", sarif)
	}
	if sarif.Runs[0].Results[0].RuleID != "EXPLICIT_RULE" {
		t.Fatalf("rule id = %q, want EXPLICIT_RULE", sarif.Runs[0].Results[0].RuleID)
	}
}

func TestBuildInspectCompactSummary(t *testing.T) {
	report := inspectReport{
		SchemaVersion: reportSchemaVersion,
		PreRelease:    true,
		Source: source{
			Input: "./fixture",
			Kind:  "local-dir",
		},
		Decision: "REJECTED",
		Findings: []inspectFinding{
			{ID: "A", Severity: "critical"},
			{ID: "B", Severity: "high"},
			{ID: "C", Severity: "medium"},
			{ID: "D", Severity: "low"},
		},
	}

	got := buildInspectCompactSummary(report)
	required := []string{
		"inspect decision=REJECTED",
		"findings=4",
		"critical=1",
		"high=1",
		"medium=1",
		"low=1",
		"source_kind=local-dir",
	}
	for _, token := range required {
		if !strings.Contains(got, token) {
			t.Fatalf("summary should include %q, got %q", token, got)
		}
	}
}

func TestValidateLocalDirInspectSource(t *testing.T) {
	writeSkillDir := func(t *testing.T, dirName, skillBody string) string {
		t.Helper()
		base := t.TempDir()
		dir := filepath.Join(base, dirName)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skillBody), 0o644); err != nil {
			t.Fatalf("write SKILL.md: %v", err)
		}
		return dir
	}

	t.Run("accepts matching directory and skill name", func(t *testing.T) {
		dir := writeSkillDir(t, "valid-skill", "---\nname: valid-skill\ndescription: Use when validating matching names.\n---\n")
		if err := validateLocalDirInspectSource(dir); err != nil {
			t.Fatalf("validateLocalDirInspectSource() error = %v", err)
		}
	})

	t.Run("rejects name mismatch with parent directory", func(t *testing.T) {
		dir := writeSkillDir(t, "different-dir", "---\nname: valid-skill\ndescription: Use when validating mismatch detection.\n---\n")
		err := validateLocalDirInspectSource(dir)
		if err == nil || !strings.Contains(err.Error(), "frontmatter name must match directory name") {
			t.Fatalf("expected directory mismatch error, got %v", err)
		}
	})

	t.Run("rejects source directory symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		target := writeSkillDir(t, "target-skill", "---\nname: target-skill\ndescription: Use when testing source symlink rejection.\n---\n")
		link := filepath.Join(t.TempDir(), "skill-link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("create source symlink: %v", err)
		}

		err := validateLocalDirInspectSource(link)
		if err == nil || !strings.Contains(err.Error(), skillpkg.RuleInspectSourceSymlink) {
			t.Fatalf("expected source symlink rejection, got %v", err)
		}
	})

	t.Run("rejects source path when ancestor directory is symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		base := t.TempDir()
		realParent := filepath.Join(base, "real-parent")
		if err := os.Mkdir(realParent, 0o755); err != nil {
			t.Fatalf("mkdir real parent: %v", err)
		}
		realSkill := filepath.Join(realParent, "ancestor-skill")
		if err := os.Mkdir(realSkill, 0o755); err != nil {
			t.Fatalf("mkdir real skill dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(realSkill, "SKILL.md"), []byte("---\nname: ancestor-skill\ndescription: Use when testing ancestor symlink source rejection.\n---\n"), 0o644); err != nil {
			t.Fatalf("write SKILL.md: %v", err)
		}

		linkParent := filepath.Join(base, "link-parent")
		if err := os.Symlink("real-parent", linkParent); err != nil {
			t.Fatalf("create ancestor symlink: %v", err)
		}

		err := validateLocalDirInspectSource(filepath.Join(linkParent, "ancestor-skill"))
		if err == nil || !strings.Contains(err.Error(), skillpkg.RuleInspectSourceSymlink) {
			t.Fatalf("expected ancestor source symlink rejection, got %v", err)
		}
	})

	t.Run("rejects symlinked SKILL.md in source directory", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		base := t.TempDir()
		dir := filepath.Join(base, "symlinked-skill")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir skill dir: %v", err)
		}
		target := filepath.Join(base, "real-skill.md")
		if err := os.WriteFile(target, []byte("---\nname: symlinked-skill\ndescription: Use when testing SKILL symlink rejection.\n---\n"), 0o644); err != nil {
			t.Fatalf("write real SKILL target: %v", err)
		}
		if err := os.Symlink("../real-skill.md", filepath.Join(dir, "SKILL.md")); err != nil {
			t.Fatalf("create SKILL.md symlink: %v", err)
		}

		err := validateLocalDirInspectSource(dir)
		if err == nil || !strings.Contains(err.Error(), skillpkg.RuleFrontmatterSymlink) {
			t.Fatalf("expected SKILL symlink rejection, got %v", err)
		}
	})

	t.Run("rejects non-regular SKILL.md in source directory", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "special-skill")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir skill dir: %v", err)
		}
		if err := os.Mkdir(filepath.Join(dir, "SKILL.md"), 0o755); err != nil {
			t.Fatalf("mkdir special SKILL path: %v", err)
		}

		err := validateLocalDirInspectSource(dir)
		if err == nil || !strings.Contains(err.Error(), skillpkg.RuleFrontmatterSpecialFile) {
			t.Fatalf("expected non-regular SKILL rejection, got %v", err)
		}
	})
}

func TestPrepareArchiveInspectSource(t *testing.T) {
	t.Run("accepts valid archive and returns cleanup", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "clean.zip")
		createZipArchive(t, archivePath, map[string]string{
			"clean-skill/SKILL.md": "---\nname: clean-skill\ndescription: Use when testing archive prepare.\n---\n",
		})

		root, cleanup, err := prepareArchiveInspectSource(archivePath, "zip")
		if err != nil {
			t.Fatalf("prepareArchiveInspectSource() error = %v", err)
		}
		if cleanup == nil {
			t.Fatal("cleanup should not be nil")
		}
		if filepath.Base(root) != "clean-skill" {
			t.Fatalf("root=%q, want clean-skill directory", root)
		}
		cleanup()
	})

	t.Run("rejects missing archive path", func(t *testing.T) {
		_, _, err := prepareArchiveInspectSource(filepath.Join(t.TempDir(), "missing.zip"), "zip")
		if err == nil || !strings.Contains(err.Error(), "failed to open zip archive") {
			t.Fatalf("expected zip-open error, got %v", err)
		}
	})

	t.Run("rejects archive without skill root", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "no-skill.zip")
		createZipArchive(t, archivePath, map[string]string{
			"docs/readme.md": "no skill here",
		})

		_, _, err := prepareArchiveInspectSource(archivePath, "zip")
		if err == nil || !strings.Contains(err.Error(), "single top-level directory") {
			t.Fatalf("expected missing-skill-root error, got %v", err)
		}
	})

	t.Run("rejects archive with invalid skill frontmatter", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "invalid.zip")
		createZipArchive(t, archivePath, map[string]string{
			"bad-skill/SKILL.md": "# missing frontmatter",
		})

		_, _, err := prepareArchiveInspectSource(archivePath, "zip")
		if err == nil || !strings.Contains(err.Error(), "must start with YAML frontmatter") {
			t.Fatalf("expected frontmatter validation error, got %v", err)
		}
	})

	t.Run("rejects symlink archive source path", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		base := t.TempDir()
		realArchive := filepath.Join(base, "clean.zip")
		createZipArchive(t, realArchive, map[string]string{
			"clean-skill/SKILL.md": "---\nname: clean-skill\ndescription: Use when testing archive symlink source rejection.\n---\n",
		})
		linkArchive := filepath.Join(base, "clean-link.zip")
		if err := os.Symlink("clean.zip", linkArchive); err != nil {
			t.Fatalf("create archive symlink: %v", err)
		}

		_, _, err := prepareArchiveInspectSource(linkArchive, "zip")
		if err == nil || !strings.Contains(err.Error(), "ARCHIVE_SOURCE_SYMLINK_DETECTED") {
			t.Fatalf("expected archive source symlink rejection, got %v", err)
		}
	})

	t.Run("rejects archive source path when ancestor directory is symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		base := t.TempDir()
		realParent := filepath.Join(base, "real-parent")
		if err := os.Mkdir(realParent, 0o755); err != nil {
			t.Fatalf("mkdir real parent: %v", err)
		}
		archivePath := filepath.Join(realParent, "clean.zip")
		createZipArchive(t, archivePath, map[string]string{
			"clean-skill/SKILL.md": "---\nname: clean-skill\ndescription: Use when testing archive ancestor symlink source rejection.\n---\n",
		})
		linkParent := filepath.Join(base, "link-parent")
		if err := os.Symlink("real-parent", linkParent); err != nil {
			t.Fatalf("create parent symlink: %v", err)
		}

		_, _, err := prepareArchiveInspectSource(filepath.Join(linkParent, "clean.zip"), "zip")
		if err == nil || !strings.Contains(err.Error(), "ARCHIVE_SOURCE_SYMLINK_DETECTED") {
			t.Fatalf("expected archive source ancestor symlink rejection, got %v", err)
		}
	})
}

func TestPrepareInspectSource(t *testing.T) {
	t.Run("unsupported source kind fails closed", func(t *testing.T) {
		root, cleanup, err := prepareInspectSource("github:org/repo//skill@main", "github-source")
		if err == nil || !strings.Contains(err.Error(), "unsupported inspect source kind") {
			t.Fatalf("expected unsupported source kind error, got %v", err)
		}
		if root != "" {
			t.Fatalf("root = %q, want empty", root)
		}
		if cleanup != nil {
			t.Fatal("cleanup should be nil for unsupported source kind")
		}
	})

	t.Run("local source returns root", func(t *testing.T) {
		rootDir := t.TempDir()
		skillDir := filepath.Join(rootDir, "valid-skill")
		if err := os.Mkdir(skillDir, 0o755); err != nil {
			t.Fatalf("mkdir skill dir: %v", err)
		}
		skill := "---\nname: valid-skill\ndescription: Use when testing prepare local source.\n---\n"
		if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(skill), 0o644); err != nil {
			t.Fatalf("write SKILL.md: %v", err)
		}

		root, cleanup, err := prepareInspectSource(skillDir, "local-dir")
		if err != nil {
			t.Fatalf("prepareInspectSource() error = %v", err)
		}
		if root != skillDir {
			t.Fatalf("root = %q, want %q", root, skillDir)
		}
		if cleanup != nil {
			t.Fatal("cleanup should be nil for local source")
		}
	})
}

type testTarEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

func createZipArchive(t *testing.T, path string, files map[string]string) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip archive: %v", err)
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

func createTarArchive(t *testing.T, path string, entries []testTarEntry) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tar archive: %v", err)
	}
	defer out.Close()

	tw := tar.NewWriter(out)
	writeTarEntries(t, tw, entries)
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
}

func createTarGzArchive(t *testing.T, path string, entries []testTarEntry) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tar.gz archive: %v", err)
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

func writeTarEntries(t *testing.T, tw *tar.Writer, entries []testTarEntry) {
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
			if _, err := tw.Write(body); err != nil {
				t.Fatalf("write tar body %s: %v", entry.name, err)
			}
		}
	}
}
