package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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

	t.Run("parses compact format", func(t *testing.T) {
		got, err := parseFetchArgs([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--format", "compact"})
		if err != nil {
			t.Fatalf("parseFetchArgs() error = %v", err)
		}
		if got.Out != "/tmp/q" || got.Format != "compact" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})

	t.Run("parses sarif format", func(t *testing.T) {
		got, err := parseFetchArgs([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--format", "sarif"})
		if err != nil {
			t.Fatalf("parseFetchArgs() error = %v", err)
		}
		if got.Out != "/tmp/q" || got.Format != "sarif" {
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

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:owner_name/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(invalid owner format) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include parse error for invalid owner format, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:Owner/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(uppercase owner) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include parse error for uppercase owner, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:owner/Repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(uppercase repo) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include parse error for uppercase repo, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:owner/.repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(repo leading dot) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include parse error for repo leading dot, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:owner/repo.//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(repo trailing dot) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include parse error for repo trailing dot, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:owner/repo.git//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(repo .git suffix) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include parse error for repo .git suffix, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:owner/re..po//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(repo consecutive dots) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include parse error for repo consecutive dots, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/demo@8F3C2D1A4B5C6D7E8F901234567890ABCDEF1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(uppercase sha) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for uppercase sha, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/demo@\n8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(control-char source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for control-char source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/demo@shadow@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(path-at source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for path-at source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills:demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(path-colon source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for path-colon source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/con@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(path-reserved device source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for reserved-device path source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/COM¹.txt@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(path-reserved superscript device source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for reserved superscript-device path source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/\u202edemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(path-bidi-control source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for path-bidi-control source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/ demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(path-segment-space source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for path-segment-space source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/demo.@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(path-segment-trailing-dot source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for path-segment-trailing-dot source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo// skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(path-space source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for path-space source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills//demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(non-canonical path source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for non-canonical path source, got %q", stderr.String())
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

	t.Run("compact output is single-line summary", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "compact-fetch-skill")
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return sourceDir, nil, nil
		}
		outRoot := t.TempDir()

		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetch([]string{
			"github:org/repo//skills/compact-fetch-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			"--out", outRoot,
			"--format", "compact",
		}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("runFetch(compact) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for compact output, got %q", stderr.String())
		}
		line := strings.TrimSpace(stdout.String())
		if strings.Contains(line, "\n") {
			t.Fatalf("compact output should be single-line, got %q", line)
		}
		for _, marker := range []string{
			"fetch decision=FETCHED",
			"source_kind=github-source",
			"source=\"github:org/repo//skills/compact-fetch-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234\"",
			"output=",
		} {
			if !strings.Contains(line, marker) {
				t.Fatalf("compact output missing %q: %q", marker, line)
			}
		}
	})

	t.Run("sarif output emits single run with fetched decision", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "sarif-fetch-skill")
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return sourceDir, nil, nil
		}
		outRoot := t.TempDir()

		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetch([]string{
			"github:org/repo//skills/sarif-fetch-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			"--out", outRoot,
			"--format", "sarif",
		}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("runFetch(sarif) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif output, got %q", stderr.String())
		}

		var sarif inspectSARIFReport
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 {
			t.Fatalf("sarif runs = %d, want 1", len(sarif.Runs))
		}
		if sarif.Runs[0].Properties.Decision != "FETCHED" {
			t.Fatalf("sarif decision = %q, want FETCHED", sarif.Runs[0].Properties.Decision)
		}
		if len(sarif.Runs[0].Results) != 0 {
			t.Fatalf("sarif results should be empty for fetch success, got %d", len(sarif.Runs[0].Results))
		}
		if !sarif.Runs[0].Invocations[0].ExecutionSuccessful {
			t.Fatal("sarif invocation executionSuccessful should be true for fetch success")
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
		if strings.Contains(stdout.String(), "\"rule_id\":") {
			t.Fatalf("stdout should omit rule_id for non-rule parse errors, got %q", stdout.String())
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
		if strings.Contains(stdout.String(), "\"rule_id\":") {
			t.Fatalf("stdout should omit rule_id for non-rule source errors, got %q", stdout.String())
		}
	})

	t.Run("sarif mode failures emit machine-readable error report", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder

		code := runFetch([]string{"--format", "sarif"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(sarif parse error) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif parse error, got %q", stderr.String())
		}

		var sarif inspectSARIFReport
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 {
			t.Fatalf("sarif runs = %d, want 1", len(sarif.Runs))
		}
		run := sarif.Runs[0]
		if run.Properties.Decision != "ERROR" {
			t.Fatalf("decision = %q, want ERROR", run.Properties.Decision)
		}
		if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
			t.Fatalf("invocation executionSuccessful should be false, got %+v", run.Invocations)
		}
		if len(run.Results) != 1 {
			t.Fatalf("sarif results = %d, want 1", len(run.Results))
		}
		if run.Results[0].RuleID != fetchErrorCodeArgsInvalid {
			t.Fatalf("rule id = %q, want %q", run.Results[0].RuleID, fetchErrorCodeArgsInvalid)
		}
		if !strings.Contains(run.Properties.Note, "error_code="+fetchErrorCodeArgsInvalid) {
			t.Fatalf("note should include error_code, got %q", run.Properties.Note)
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"../../fixtures/clean-skill", "--out", t.TempDir(), "--format", "sarif"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(sarif unsupported source) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif source error, got %q", stderr.String())
		}
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
			t.Fatalf("unexpected sarif structure: %+v", sarif)
		}
		if sarif.Runs[0].Results[0].RuleID != fetchErrorCodeSourceUnsupported {
			t.Fatalf("rule id = %q, want %q", sarif.Runs[0].Results[0].RuleID, fetchErrorCodeSourceUnsupported)
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

		// uppercase commit sha
		code = runFetch([]string{"github:org/repo//skills/x@8F3C2D1A4B5C6D7E8F901234567890ABCDEF1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code for uppercase sha, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// control character in source
		code = runFetch([]string{"github:org/repo//skills/x@\n8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code for control-char source, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// surrounding whitespace in path
		code = runFetch([]string{"github:org/repo// skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code for path-space source, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// non-canonical path segments
		code = runFetch([]string{"github:org/repo//skills//x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code for non-canonical path source, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
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

		// source download/materialize failure with rule-prefixed error
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return "", nil, errors.New("ARCHIVE_PATH_ESCAPE: archive entry escaped source root")
		}
		code = runFetch([]string{"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceDownloadFailed) {
			t.Fatalf("expected source-download-failed code for rule-prefixed error, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \"ARCHIVE_PATH_ESCAPE\"") {
			t.Fatalf("stdout should include source download rule_id, got %q", stdout.String())
		}
		stdout.Reset()
		stderr.Reset()

		// source download/materialize failure with https rule-prefixed error
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return "", nil, errors.New("GITHUB_ARCHIVE_SCHEME_INVALID: github archive URL must use https")
		}
		code = runFetch([]string{"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceDownloadFailed) {
			t.Fatalf("expected source-download-failed code for https rule-prefixed error, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \"GITHUB_ARCHIVE_SCHEME_INVALID\"") {
			t.Fatalf("stdout should include https rule_id, got %q", stdout.String())
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
		stdout.Reset()
		stderr.Reset()

		// source metadata write failure with rule-prefixed error
		writeSourceMetaFunc = func(skillRoot string, meta sourceMetadata) error {
			return errors.New(ruleSourceMetadataSymlink + ": source metadata file must not be a symlink")
		}
		code = runFetch([]string{"github:org/repo//skills/json-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeMetadataWriteFailed) {
			t.Fatalf("expected metadata-write-failed code for rule-prefixed error, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleSourceMetadataSymlink+"\"") {
			t.Fatalf("stdout should include metadata-write rule_id, got %q", stdout.String())
		}
		writeSourceMetaFunc = writeSourceMetadata
	})
}

func TestRunFetchRejectsSymlinkOutputRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on windows")
	}

	origFetch := fetchGitHubSkill
	t.Cleanup(func() { fetchGitHubSkill = origFetch })

	sourceDir := createSkillSourceForInstallTest(t, "fetch-symlink-out")
	fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
		return sourceDir, nil, nil
	}

	base := t.TempDir()
	realOut := filepath.Join(base, "real-out")
	if err := os.Mkdir(realOut, 0o755); err != nil {
		t.Fatalf("mkdir real out root: %v", err)
	}
	symlinkOut := filepath.Join(base, "out-link")
	if err := os.Symlink("real-out", symlinkOut); err != nil {
		t.Fatalf("create output root symlink: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runFetch([]string{
		"github:org/repo//skills/fetch-symlink-out@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
		"--out", symlinkOut,
		"--format", "json",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runFetch(symlink out) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json errors, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+fetchErrorCodeOutputPrepareFailed+"\"") {
		t.Fatalf("stdout should include output-prepare-failed code, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleFetchOutputSymlink+"\"") {
		t.Fatalf("stdout should include symlink rule_id, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runFetch([]string{
		"github:org/repo//skills/fetch-symlink-out@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
		"--out", symlinkOut,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runFetch(human symlink out) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty for human errors, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), ruleFetchOutputSymlink) {
		t.Fatalf("stderr should include symlink rule marker, got %q", stderr.String())
	}
}

func TestRunFetchRejectsSymlinkOutputEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on windows")
	}

	origFetch := fetchGitHubSkill
	t.Cleanup(func() { fetchGitHubSkill = origFetch })

	sourceDir := createSkillSourceForInstallTest(t, "fetch-symlink-entry")
	fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
		return sourceDir, nil, nil
	}

	base := t.TempDir()
	outRoot := filepath.Join(base, "out")
	if err := os.Mkdir(outRoot, 0o755); err != nil {
		t.Fatalf("mkdir out root: %v", err)
	}
	realExisting := filepath.Join(base, "real-existing")
	if err := os.Mkdir(realExisting, 0o755); err != nil {
		t.Fatalf("mkdir real existing dir: %v", err)
	}
	if err := os.Symlink("../real-existing", filepath.Join(outRoot, "fetch-symlink-entry")); err != nil {
		t.Fatalf("create output entry symlink: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runFetch([]string{
		"github:org/repo//skills/fetch-symlink-entry@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
		"--out", outRoot,
		"--format", "json",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runFetch(symlink output entry) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json errors, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+fetchErrorCodeCopyFailed+"\"") {
		t.Fatalf("stdout should include copy-failed error code, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleFetchOutputEntrySymlink+"\"") {
		t.Fatalf("stdout should include output-entry symlink rule_id, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runFetch([]string{
		"github:org/repo//skills/fetch-symlink-entry@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
		"--out", outRoot,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runFetch(human symlink output entry) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty for human errors, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), ruleFetchOutputEntrySymlink) {
		t.Fatalf("stderr should include output-entry symlink rule marker, got %q", stderr.String())
	}
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
	if !fetchArgsRequestSARIF([]string{"--format", "sarif"}) {
		t.Fatal("expected sarif format detection")
	}
	if !fetchArgsRequestSARIF([]string{"--format=sarif"}) {
		t.Fatal("expected equals sarif format detection")
	}
	if fetchArgsRequestSARIF([]string{"--format", "human"}) {
		t.Fatal("human format should not be detected as sarif")
	}

	if got := extractFetchSourceArg([]string{"--out", "/tmp/q", "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}); !strings.HasPrefix(got, "github:") {
		t.Fatalf("unexpected extracted source arg: %q", got)
	}
	if got := extractFetchSourceArg([]string{"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}); !strings.HasPrefix(got, "github:") {
		t.Fatalf("unexpected extracted source arg: %q", got)
	}
}

func TestBuildFetchCompactSummary(t *testing.T) {
	report := fetchReport{
		Source: source{
			Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		},
		Output:   "/tmp/q/x",
		Decision: "FETCHED",
	}
	got := buildFetchCompactSummary(report)
	required := []string{
		"fetch decision=FETCHED",
		"source_kind=github-source",
		"source=\"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234\"",
		"output=\"/tmp/q/x\"",
	}
	for _, marker := range required {
		if !strings.Contains(got, marker) {
			t.Fatalf("compact summary missing marker %q: %q", marker, got)
		}
	}
}

func TestBuildFetchSARIFReport(t *testing.T) {
	report := fetchReport{
		SchemaVersion: reportSchemaVersion,
		Source: source{
			Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		},
		Output:   "/tmp/q/x",
		Decision: "FETCHED",
		Note:     "pre-release fetch note",
	}
	sarif := buildFetchSARIFReport(report)
	if sarif.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if run.Properties.Decision != "FETCHED" {
		t.Fatalf("decision = %q, want FETCHED", run.Properties.Decision)
	}
	if run.Properties.SourceKind != "github-source" {
		t.Fatalf("source kind = %q, want github-source", run.Properties.SourceKind)
	}
	if len(run.Results) != 0 {
		t.Fatalf("results should be empty, got %d", len(run.Results))
	}
}

func TestBuildFetchSARIFErrorReport(t *testing.T) {
	report := fetchErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     fetchErrorCodeSourceDownloadFailed,
		Message:       "download failed",
		Source: source{
			Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		},
		Output: "/tmp/q/x",
		Note:   "fetch failed while downloading",
	}
	sarif := buildFetchSARIFErrorReport(report)
	if sarif.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
	if run.Results[0].RuleID != fetchErrorCodeSourceDownloadFailed {
		t.Fatalf("rule id = %q, want %q", run.Results[0].RuleID, fetchErrorCodeSourceDownloadFailed)
	}
	if run.Results[0].Level != "error" {
		t.Fatalf("level = %q, want error", run.Results[0].Level)
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("invocation executionSuccessful should be false, got %+v", run.Invocations)
	}
	if run.Properties.Decision != "ERROR" {
		t.Fatalf("decision = %q, want ERROR", run.Properties.Decision)
	}
}

func TestWriteFetchSARIFErrorPreservesExplicitRuleID(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := writeFetchSARIFError(&stdout, &stderr, fetchErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     fetchErrorCodeSourceDownloadFailed,
		RuleID:        "EXPLICIT_RULE",
		Message:       "EXPLICIT_RULE: synthetic fetch error",
		Source: source{
			Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		},
		Note: "test",
	})
	if code != 1 {
		t.Fatalf("writeFetchSARIFError() code = %d, want 1", code)
	}
	var sarif inspectSARIFReport
	if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
		t.Fatalf("sarif parse failed: %v", err)
	}
	if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("unexpected sarif structure: %+v", sarif)
	}
	if sarif.Runs[0].Results[0].RuleID != "EXPLICIT_RULE" {
		t.Fatalf("rule id = %q, want EXPLICIT_RULE", sarif.Runs[0].Results[0].RuleID)
	}
}

func TestWriteFetchJSONErrorPreservesExplicitRuleID(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := writeFetchJSONError(&stdout, &stderr, fetchErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     fetchErrorCodeSourceDownloadFailed,
		RuleID:        "EXPLICIT_RULE",
		Message:       "EXPLICIT_RULE: synthetic fetch error",
		Source: source{
			Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		},
		Note: "test",
	})
	if code != 1 {
		t.Fatalf("writeFetchJSONError() code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "\"rule_id\": \"EXPLICIT_RULE\"") {
		t.Fatalf("stdout should preserve explicit rule_id, got %q", stdout.String())
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

		if runtime.GOOS != "windows" {
			symlinkOut := filepath.Join(t.TempDir(), "out")
			if err := os.Mkdir(symlinkOut, 0o755); err != nil {
				t.Fatalf("mkdir symlink out: %v", err)
			}
			realExisting := filepath.Join(t.TempDir(), "real-existing")
			if err := os.Mkdir(realExisting, 0o755); err != nil {
				t.Fatalf("mkdir real existing: %v", err)
			}
			if err := os.Symlink(realExisting, filepath.Join(symlinkOut, "fetch-atomic-fail")); err != nil {
				t.Fatalf("create output entry symlink: %v", err)
			}
			_, err = fetchSkillAtomic(sourceDir, symlinkOut, "fetch-atomic-fail")
			if err == nil || !strings.Contains(err.Error(), ruleFetchOutputEntrySymlink) {
				t.Fatalf("expected output-entry symlink rejection, got %v", err)
			}
		}
	})
}
