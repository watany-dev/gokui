package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func TestRunInspectGitHubSourceRejectsFloatingRef(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"inspect", "github:org/repo//skills/x@main", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeGitHubRefNotPinned+"\"") {
		t.Fatalf("stdout should include github-ref-not-pinned error code, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "requires a commit-pinned ref") {
		t.Fatalf("stdout should include commit-pinned guidance, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsInvalidSyntax(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo/path@main", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsInvalidOwnerFormat(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:owner_name/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsUppercaseOwner(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:Owner/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsUppercaseRepo(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:owner/Repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsRepoLeadingDot(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:owner/.repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsRepoTrailingDot(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:owner/repo.//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsRepoDotGitSuffix(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:owner/repo.git//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsRepoConsecutiveDots(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:owner/re..po//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsUppercaseCommitSHA(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/x@8F3C2D1A4B5C6D7E8F901234567890ABCDEF1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsControlCharacterInput(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/x@\n8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsPathContainingAtSign(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/x@shadow@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsPathContainingColon(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills:x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsWindowsReservedPathSegment(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/con@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsWindowsReservedSuperscriptPathSegment(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/COM¹.txt@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsPathContainingBidiControl(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/\u202edemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsPathContainingZeroWidthCharacter(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/\u200bdemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsPathContainingWhitespaceCharacter(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/my skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsRefContainingUnicodeWhitespace(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\u00a01234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsRefContainingZeroWidthCharacter(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\u200b1234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsRefContainingBidiControl(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\u202e1234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsPathSegmentWithLeadingSpace(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/ x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsPathSegmentWithTrailingDot(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills/x.@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsPathWithSurroundingSpaces(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo// skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceRejectsNonCanonicalPathSegments(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"inspect", "github:org/repo//skills//x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourceInvalid+"\"") {
		t.Fatalf("stdout should include source-invalid error code, got %q", stdout.String())
	}
}

func TestRunInspectGitHubSourceCommitPinnedEvaluatesContent(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	origFetch := fetchGitHubSkill
	t.Cleanup(func() { fetchGitHubSkill = origFetch })

	t.Run("clean content passes", func(t *testing.T) {
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return filepath.FromSlash("../../fixtures/clean-skill"), nil, nil
		}

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
		if code != 0 {
			t.Fatalf("Run() code = %d, want 0", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}

		var got inspectReport
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatalf("inspect json should be valid: %v", err)
		}
		if got.Decision != "PASS" {
			t.Fatalf("decision = %q, want PASS", got.Decision)
		}
		if !strings.Contains(got.Note, "github commit-pinned source") {
			t.Fatalf("note should include commit-pinned scan message, got %q", got.Note)
		}
	})

	t.Run("risky content is rejected", func(t *testing.T) {
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return filepath.FromSlash("../../fixtures/fake-prereq-skill"), nil, nil
		}

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/fake-prereq-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
		if code != 2 {
			t.Fatalf("Run() code = %d, want 2", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}

		var got inspectReport
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatalf("inspect json should be valid: %v", err)
		}
		if got.Decision != "REJECTED" {
			t.Fatalf("decision = %q, want REJECTED", got.Decision)
		}
	})

	t.Run("fetch failure surfaces error", func(t *testing.T) {
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return "", nil, os.ErrNotExist
		}

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourcePrepareFailed+"\"") {
			t.Fatalf("stdout should include source-prepare-failed code, got %q", stdout.String())
		}
	})
}
