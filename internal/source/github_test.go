package source

import "testing"

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
		}
		for _, in := range cases {
			if _, err := ParseGitHubSource(in); err == nil {
				t.Fatalf("expected parse error for %q", in)
			}
		}
	})
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
