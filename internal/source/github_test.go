package source

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"testing/quick"
)

func TestParseGitHubSource(t *testing.T) {
	t.Run("parses valid source", func(t *testing.T) {
		got, err := ParseGitHubSource("github:watany-dev/gokui//skills/pdf-helper@8f3c2d1a4b5c6d7e8f901234567890abcdef1234")
		if err != nil {
			t.Fatalf("ParseGitHubSource() error = %v", err)
		}
		if got.Owner != "watany-dev" || got.Repo != "gokui" || got.Path != "skills/pdf-helper" || got.Ref != "8f3c2d1a4b5c6d7e8f901234567890abcdef1234" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})

	t.Run("rejects invalid inputs", func(t *testing.T) {
		cases := []string{
			"git:owner/repo//path@ref",
			"github:owner/repo/path@ref",
			"github:owner/repo/extra//path@ref",
			"github:owner/repo//@ref",
			"github:owner/repo//../path@ref",
			"github:owner/repo//path",
			"github:/repo//path@ref",
			"github:owner/ repo//path@ref",
			"github: owner/repo//path@ref",
			"github:owner!/repo//path@ref",
			"github:owner/repo//path@",
			"github:owner/repo//@",
			"github:owner/repo///abs@ref",
			"github:owner/repo//./@ref",
			`github:owner/repo//skills\demo@ref`,
			"github:owner/repo//path@ 8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			"github:owner/repo//path@8f3c2d1a4b5c6d7e8f901234567890abcdef1234 ",
		}
		for _, in := range cases {
			if _, err := ParseGitHubSource(in); err == nil {
				t.Fatalf("expected parse error for %q", in)
			}
		}
	})
}

func TestParseGitHubSourcePropertyNoPanic(t *testing.T) {
	prop := func(input string) (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				ok = false
			}
		}()
		_, _ = ParseGitHubSource(input)
		return true
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatalf("ParseGitHubSource panic-safety property failed: %v", err)
	}
}

func TestNormalizeGitHubPath(t *testing.T) {
	t.Run("accepts normalized relative path", func(t *testing.T) {
		got, err := normalizeGitHubPath("skills/my-skill")
		if err != nil {
			t.Fatalf("normalizeGitHubPath() error = %v", err)
		}
		if got != "skills/my-skill" {
			t.Fatalf("normalized path = %q", got)
		}
	})

	t.Run("rejects empty and absolute and dot paths", func(t *testing.T) {
		cases := []string{"", " ", "/abs/path", ".", "./"}
		for _, in := range cases {
			if _, err := normalizeGitHubPath(in); err == nil {
				t.Fatalf("expected path error for %q", in)
			}
		}
	})

	t.Run("rejects backslash-separated paths", func(t *testing.T) {
		if _, err := normalizeGitHubPath(`skills\demo`); err == nil {
			t.Fatal("expected path error for backslash-separated path")
		}
	})
}

func TestIsCommitPinnedRef(t *testing.T) {
	if IsCommitPinnedRef("8f3c2d1") {
		t.Fatal("short SHA should not be pinned")
	}
	if !IsCommitPinnedRef("8f3c2d1a4b5c6d7e8f901234567890abcdef1234") {
		t.Fatal("full SHA should be pinned")
	}
	if IsCommitPinnedRef("main") {
		t.Fatal("branch should not be pinned")
	}
	if IsCommitPinnedRef("v1.0.0") {
		t.Fatal("tag should not be pinned")
	}
	if IsCommitPinnedRef("8f3c2z1") {
		t.Fatal("non-hex ref should not be pinned")
	}
}

func TestIsCommitPinnedRefProperty(t *testing.T) {
	hex40 := regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	prop := func(raw string) bool {
		got := IsCommitPinnedRef(raw)
		trimmed := strings.TrimSpace(raw)
		if got {
			return hex40.MatchString(trimmed)
		}
		if hex40.MatchString(trimmed) {
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatalf("IsCommitPinnedRef property failed: %v", err)
	}
}

func TestIsCommitPinnedRefPropertyKnownTrueCases(t *testing.T) {
	prop := func(suffix uint32) bool {
		ref := fmt.Sprintf("8f3c2d1a4b5c6d7e8f901234567890ab%08x", suffix)
		return IsCommitPinnedRef(ref)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 200}); err != nil {
		t.Fatalf("IsCommitPinnedRef true-case property failed: %v", err)
	}
}
