package app

import (
	"strings"
	"testing"

	policypkg "github.com/watany-dev/gokui/internal/policy"
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
