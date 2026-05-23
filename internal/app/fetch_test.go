package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func TestParseFetchArgs(t *testing.T) {
	t.Run("parses source out and format", func(t *testing.T) {
		got, err := parseFetchArgs([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--format", "json"})
		if err != nil {
			t.Fatalf("parseFetchArgs() error = %v", err)
		}
		if got.Source == "" || got.Out != "/tmp/q" || got.Format != "json" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})

	t.Run("errors", func(t *testing.T) {
		cases := [][]string{
			{},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out"},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--format"},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--format", "xml"},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--bad"},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "github:org/repo//skills/other@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q"},
		}
		for _, in := range cases {
			if _, err := parseFetchArgs(in); err == nil {
				t.Fatalf("expected parse error for args=%v", in)
			}
		}
	})

	t.Run("parses equals syntax", func(t *testing.T) {
		got, err := parseFetchArgs([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out=/tmp/q", "--format=json"})
		if err != nil {
			t.Fatalf("parseFetchArgs() error = %v", err)
		}
		if got.Out != "/tmp/q" || got.Format != "json" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})
}

func TestRunFetch(t *testing.T) {
	origFetch := fetchGitHubSkill
	origAtomic := fetchSkillAtomicFunc
	origWriteMeta := writeSourceMetaFunc
	t.Cleanup(func() { fetchGitHubSkill = origFetch })
	t.Cleanup(func() { fetchSkillAtomicFunc = origAtomic })
	t.Cleanup(func() { writeSourceMetaFunc = origWriteMeta })

	t.Run("fetches commit-pinned github source", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "demo-skill")
		cleanupCalled := false
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return sourceDir, func() { cleanupCalled = true }, nil
		}

		outRoot := filepath.Join(t.TempDir(), "q")
		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetch([]string{"github:org/repo//skills/demo-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", outRoot, "--format", "json"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("runFetch() code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}

		var report fetchReport
		if err := json.Unmarshal([]byte(stdout.String()), &report); err != nil {
			t.Fatalf("json parse failed: %v", err)
		}
		if report.Decision != "FETCHED" {
			t.Fatalf("decision = %q, want FETCHED", report.Decision)
		}
		fetchedRoot := filepath.Join(outRoot, "demo-skill")
		if _, err := os.Stat(filepath.Join(fetchedRoot, "SKILL.md")); err != nil {
			t.Fatalf("expected fetched SKILL.md: %v", err)
		}
		meta, ok, err := readSourceMetadata(fetchedRoot)
		if err != nil {
			t.Fatalf("readSourceMetadata() error = %v", err)
		}
		if !ok {
			t.Fatal("expected source metadata after fetch")
		}
		if meta.SourceKind != "github-source" || meta.SourceInput == "" {
			t.Fatalf("unexpected source metadata: %+v", meta)
		}
		if !cleanupCalled {
			t.Fatal("fetch cleanup should be called")
		}
	})

	t.Run("rejects non-github and floating refs", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetch([]string{"../../fixtures/clean-skill", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(non-github) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "github sources only") {
			t.Fatalf("stderr should include github-only message, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/demo@main", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(floating) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "commit-pinned ref") {
			t.Fatalf("stderr should include commit-pinned error, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo/path@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(invalid syntax) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include parse error, got %q", stderr.String())
		}
	})

	t.Run("propagates fetch and collision errors", func(t *testing.T) {
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return "", nil, errors.New("boom")
		}
		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetch([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(fetch error) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "boom") {
			t.Fatalf("stderr should include fetch error, got %q", stderr.String())
		}

		sourceDir := createSkillSourceForInstallTest(t, "demo-collision")
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return sourceDir, nil, nil
		}
		outRoot := filepath.Join(t.TempDir(), "q")
		if err := os.MkdirAll(filepath.Join(outRoot, "demo-collision"), 0o755); err != nil {
			t.Fatalf("mkdir collision path: %v", err)
		}
		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/demo-collision@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", outRoot}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(collision) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "already contains skill") {
			t.Fatalf("stderr should include collision error, got %q", stderr.String())
		}
	})

	t.Run("propagates metadata write errors", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "meta-write-fail-skill")
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return sourceDir, nil, nil
		}
		writeSourceMetaFunc = func(skillRoot string, meta sourceMetadata) error {
			return errors.New("metadata write failed")
		}
		defer func() { writeSourceMetaFunc = writeSourceMetadata }()

		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetch([]string{"github:org/repo//skills/meta-write-fail-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(metadata write error) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "metadata write failed") {
			t.Fatalf("stderr should include metadata write failure, got %q", stderr.String())
		}
	})

	t.Run("propagates atomic copy errors", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "atomic-fail-skill")
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return sourceDir, nil, nil
		}
		fetchSkillAtomicFunc = func(skillRoot string, outRoot string, skillName string) (string, error) {
			return "", errors.New("atomic copy failed")
		}
		defer func() { fetchSkillAtomicFunc = fetchSkillAtomic }()

		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetch([]string{"github:org/repo//skills/atomic-fail-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(atomic error) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "atomic copy failed") {
			t.Fatalf("stderr should include atomic error, got %q", stderr.String())
		}
	})

	t.Run("validates frontmatter and supports human output", func(t *testing.T) {
		bad := t.TempDir()
		if err := os.WriteFile(filepath.Join(bad, "SKILL.md"), []byte("# no frontmatter"), 0o644); err != nil {
			t.Fatalf("write bad skill: %v", err)
		}
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return bad, nil, nil
		}
		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetch([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(frontmatter error) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "must start with YAML frontmatter") {
			t.Fatalf("stderr should include frontmatter error, got %q", stderr.String())
		}

		sourceDir := createSkillSourceForInstallTest(t, "human-fetch-skill")
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return sourceDir, nil, nil
		}
		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/human-fetch-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("runFetch(human) code = %d, want 0", code)
		}
		if !strings.Contains(stdout.String(), "gokui fetch report (pre-release)") {
			t.Fatalf("stdout should include human header, got %q", stdout.String())
		}
	})

	t.Run("parse and output-root failures return exit code 1", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetch(nil, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(parse error) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "fetch source is required") {
			t.Fatalf("stderr should include parse error, got %q", stderr.String())
		}

		sourceDir := createSkillSourceForInstallTest(t, "mkdir-fail-fetch")
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return sourceDir, nil, nil
		}
		stdout.Reset()
		stderr.Reset()
		outFile := filepath.Join(t.TempDir(), "not-dir")
		if err := os.WriteFile(outFile, []byte("x"), 0o644); err != nil {
			t.Fatalf("write out file: %v", err)
		}
		code = runFetch([]string{"github:org/repo//skills/mkdir-fail-fetch@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", filepath.Join(outFile, "child")}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(out mkdir fail) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "failed to prepare fetch output root") {
			t.Fatalf("stderr should include out mkdir error, got %q", stderr.String())
		}
	})

	t.Run("json mode failures emit machine-readable error report", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder

		code := runFetch([]string{"--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(json parse error) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json parse error, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
			t.Fatalf("stdout should include error status, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+fetchErrorCodeArgsInvalid+"\"") {
			t.Fatalf("stdout should include parse error_code, got %q", stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"../../fixtures/clean-skill", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(json unsupported source) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json source error, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+fetchErrorCodeSourceUnsupported+"\"") {
			t.Fatalf("stdout should include source unsupported error_code, got %q", stdout.String())
		}
	})

	t.Run("json mode failure codes cover major branches", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "json-error-skill")
		var stdout strings.Builder
		var stderr strings.Builder

		// invalid source syntax
		code := runFetch([]string{"github:org/repo/path@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// floating ref
		code = runFetch([]string{"github:org/repo//skills/x@main", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceRefNotPinned) {
			t.Fatalf("expected ref-not-pinned code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// source download/materialize failure
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return "", nil, errors.New("download failed")
		}
		code = runFetch([]string{"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceDownloadFailed) {
			t.Fatalf("expected source-download-failed code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// invalid skill frontmatter
		badSkill := t.TempDir()
		if err := os.WriteFile(filepath.Join(badSkill, "SKILL.md"), []byte("# bad"), 0o644); err != nil {
			t.Fatalf("write bad SKILL.md: %v", err)
		}
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return badSkill, nil, nil
		}
		code = runFetch([]string{"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSkillInvalid) {
			t.Fatalf("expected skill-invalid code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// output prepare failure
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return sourceDir, nil, nil
		}
		outFile := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(outFile, []byte("x"), 0o644); err != nil {
			t.Fatalf("write out file: %v", err)
		}
		code = runFetch([]string{"github:org/repo//skills/json-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", filepath.Join(outFile, "child"), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeOutputPrepareFailed) {
			t.Fatalf("expected output-prepare-failed code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// copy failure
		fetchSkillAtomicFunc = func(skillRoot string, outRoot string, skillName string) (string, error) {
			return "", errors.New("copy failed")
		}
		code = runFetch([]string{"github:org/repo//skills/json-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeCopyFailed) {
			t.Fatalf("expected copy-failed code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		fetchSkillAtomicFunc = fetchSkillAtomic
		stdout.Reset()
		stderr.Reset()

		// digest failure
		fetchSkillAtomicFunc = func(skillRoot string, outRoot string, skillName string) (string, error) {
			return filepath.Join(outRoot, "missing-after-copy"), nil
		}
		code = runFetch([]string{"github:org/repo//skills/json-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeDigestFailed) {
			t.Fatalf("expected digest-failed code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		fetchSkillAtomicFunc = fetchSkillAtomic
		stdout.Reset()
		stderr.Reset()

		// source metadata write failure
		writeSourceMetaFunc = func(skillRoot string, meta sourceMetadata) error {
			return errors.New("meta write failed")
		}
		code = runFetch([]string{"github:org/repo//skills/json-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeMetadataWriteFailed) {
			t.Fatalf("expected metadata-write-failed code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		writeSourceMetaFunc = writeSourceMetadata
	})
}

func TestFetchHelperFunctions(t *testing.T) {
	if !fetchArgsRequestJSON([]string{"--format", "json"}) {
		t.Fatal("expected json format detection")
	}
	if !fetchArgsRequestJSON([]string{"--format=json"}) {
		t.Fatal("expected equals json format detection")
	}
	if fetchArgsRequestJSON([]string{"--format", "human"}) {
		t.Fatal("human format should not be detected as json")
	}

	if got := extractFetchSourceArg([]string{"--out", "/tmp/q", "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}); !strings.HasPrefix(got, "github:") {
		t.Fatalf("unexpected extracted source arg: %q", got)
	}
	if got := extractFetchSourceArg([]string{"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}); !strings.HasPrefix(got, "github:") {
		t.Fatalf("unexpected extracted source arg: %q", got)
	}
}

func TestFetchSkillAtomic(t *testing.T) {
	sourceDir := createSkillSourceForInstallTest(t, "atomic-fetch-skill")
	outRoot := filepath.Join(t.TempDir(), "q")
	if err := os.MkdirAll(outRoot, 0o755); err != nil {
		t.Fatalf("mkdir out root: %v", err)
	}

	dest, err := fetchSkillAtomic(sourceDir, outRoot, "atomic-fetch-skill")
	if err != nil {
		t.Fatalf("fetchSkillAtomic() error = %v", err)
	}
	if dest != filepath.Join(outRoot, "atomic-fetch-skill") {
		t.Fatalf("dest = %q", dest)
	}

	if _, err := os.Stat(filepath.Join(dest, "SKILL.md")); err != nil {
		t.Fatalf("expected SKILL.md after fetch copy: %v", err)
	}

	t.Run("fails for bad output root and stat errors", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "fetch-atomic-fail")
		targetFile := filepath.Join(t.TempDir(), "target-file")
		if err := os.WriteFile(targetFile, []byte("x"), 0o644); err != nil {
			t.Fatalf("write target file: %v", err)
		}
		_, err := fetchSkillAtomic(sourceDir, targetFile, "fetch-atomic-fail")
		if err == nil || !strings.Contains(err.Error(), "failed to check fetch output target") {
			t.Fatalf("expected check-target error, got %v", err)
		}

		missingRoot := filepath.Join(t.TempDir(), "missing", "q")
		_, err = fetchSkillAtomic(sourceDir, missingRoot, "fetch-atomic-fail")
		if err == nil || !strings.Contains(err.Error(), "failed to create fetch staging directory") {
			t.Fatalf("expected staging error, got %v", err)
		}

		_, err = fetchSkillAtomic(filepath.Join(t.TempDir(), "missing-source"), outRoot, "fetch-atomic-fail")
		if err == nil {
			t.Fatal("expected copy error for missing source")
		}

		_, err = fetchSkillAtomic(sourceDir, outRoot, "nested/path")
		if err == nil || !strings.Contains(err.Error(), "failed to finalize fetch") {
			t.Fatalf("expected rename error for nested path, got %v", err)
		}
	})
}
