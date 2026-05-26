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
			"github:./repo//path@ref",
			"github:../repo//path@ref",
			"github:owner/.//path@ref",
			"github:owner/..//path@ref",
			"github:owner/repo//@ref",
			"github:owner/repo//../path@ref",
			"github:owner/repo//skills//demo@ref",
			"github:owner/repo//skills/./demo@ref",
			"github:owner/repo//skills/demo/@ref",
			"github:owner/repo//skills/demo/../other@ref",
			"github:owner/repo//path",
			"github:/repo//path@ref",
			"github:owner/ repo//path@ref",
			"github: owner/repo//path@ref",
			"github:owner!/repo//path@ref",
			"github:owner_name/repo//path@ref",
			"github:-owner/repo//path@ref",
			"github:owner-/repo//path@ref",
			"github:owner--name/repo//path@ref",
			"github:Owner/repo//path@ref",
			"github:owner/Repo//path@ref",
			"github:owner/.repo//path@ref",
			"github:owner/repo.//path@ref",
			"github:owner/repo.git//path@ref",
			"github:owner/repo.GIT//path@ref",
			"github:owner/re..po//path@ref",
			"github:owner/repo//path@",
			"github:owner/repo//@",
			"github:owner/repo///abs@ref",
			"github:owner/repo//./@ref",
			"github:owner/repo//skills/demo@shadow@ref",
			`github:owner/repo//skills\demo@ref`,
			"github:owner/repo//path@ 8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			"github:owner/repo//path@8f3c2d1a4b5c6d7e8f901234567890abcdef1234 ",
			"github:owner/repo//path@8F3C2D1A4B5C6D7E8F901234567890ABCDEF1234",
			"github:owner/repo//path@\n8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			"github:owner/repo//skills/\x1fhelper@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			"github:owner\x7f/repo//path@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			"github:owner/repo// skills/path@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			"github:owner/repo//skills/path @8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
		}
		for _, in := range cases {
			if _, err := ParseGitHubSource(in); err == nil {
				t.Fatalf("expected parse error for %q", in)
			}
		}
	})

	t.Run("enforces length bounds", func(t *testing.T) {
		ownerMax := strings.Repeat("a", maxGitHubOwnerChars)
		repoMax := strings.Repeat("b", maxGitHubRepoChars)
		pathMax := strings.Repeat("c", maxGitHubPathChars)
		refMax := strings.Repeat("d", maxGitHubRefChars)
		valid := fmt.Sprintf("github:%s/%s//%s@%s", ownerMax, repoMax, pathMax, refMax)
		if _, err := ParseGitHubSource(valid); err != nil {
			t.Fatalf("expected max-length source to pass, got %v", err)
		}

		cases := []struct {
			name  string
			input string
		}{
			{
				name:  "owner too long",
				input: fmt.Sprintf("github:%s/x//skills/demo@main", strings.Repeat("o", maxGitHubOwnerChars+1)),
			},
			{
				name:  "repo too long",
				input: fmt.Sprintf("github:owner/%s//skills/demo@main", strings.Repeat("r", maxGitHubRepoChars+1)),
			},
			{
				name:  "path too long",
				input: fmt.Sprintf("github:owner/repo//%s@main", strings.Repeat("p", maxGitHubPathChars+1)),
			},
			{
				name:  "ref too long",
				input: fmt.Sprintf("github:owner/repo//skills/demo@%s", strings.Repeat("f", maxGitHubRefChars+1)),
			},
			{
				name:  "total input too long",
				input: "github:owner/repo//skills/demo@" + strings.Repeat("x", maxGitHubSourceInputChars),
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := ParseGitHubSource(tc.input); err == nil {
					t.Fatalf("expected parse error for over-limit input: %s", tc.name)
				}
			})
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

	t.Run("rejects surrounding spaces in path", func(t *testing.T) {
		cases := []string{" skills/demo", "skills/demo ", "\tskills/demo"}
		for _, in := range cases {
			if _, err := normalizeGitHubPath(in); err == nil {
				t.Fatalf("expected path-space error for %q", in)
			}
		}
	})

	t.Run("rejects non-canonical path segments", func(t *testing.T) {
		cases := []string{"skills//demo", "skills/./demo", "skills/demo/", "skills/a/../demo"}
		for _, in := range cases {
			if _, err := normalizeGitHubPath(in); err == nil {
				t.Fatalf("expected canonical-path error for %q", in)
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
	if IsCommitPinnedRef("8F3C2D1A4B5C6D7E8F901234567890ABCDEF1234") {
		t.Fatal("uppercase full SHA should not be pinned")
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
	if IsCommitPinnedRef(" 8f3c2d1a4b5c6d7e8f901234567890abcdef1234 ") {
		t.Fatal("whitespace-padded SHA should not be pinned")
	}
}

func TestIsCommitPinnedRefProperty(t *testing.T) {
	hex40 := regexp.MustCompile(`^[0-9a-f]{40}$`)
	prop := func(raw string) bool {
		got := IsCommitPinnedRef(raw)
		if got {
			return hex40.MatchString(raw)
		}
		if hex40.MatchString(raw) {
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
