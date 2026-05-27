package app

import (
	"strings"
	"testing"
)

func TestRunFetchSourceValidation(t *testing.T) {
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
		code = runFetch([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f90\u00a01234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(ref-unicode-whitespace source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for ref-unicode-whitespace source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f90\u200b1234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(ref-zero-width source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for ref-zero-width source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		invalidUTF8Source := string([]byte("github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234\xff"))
		code = runFetch([]string{invalidUTF8Source, "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(non-UTF-8 source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "must be valid UTF-8") {
			t.Fatalf("stderr should include UTF-8 validation detail for non-UTF-8 source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f90\u202e1234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(ref-bidi-control source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for ref-bidi-control source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:or\u00a0g/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(owner-unicode-whitespace source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for owner-unicode-whitespace source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/re\u200bpo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(repo-zero-width source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for repo-zero-width source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:or\U000E0001g/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(owner-unicode-tag source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for owner-unicode-tag source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/re\ufe0fpo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(repo-variation-selector source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for repo-variation-selector source, got %q", stderr.String())
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
		code = runFetch([]string{"github:org/repo//skills/\u200bdemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(path-zero-width source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for path-zero-width source, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/my skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(path-whitespace source) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include invalid source message for path-whitespace source, got %q", stderr.String())
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

}
