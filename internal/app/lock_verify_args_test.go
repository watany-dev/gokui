package app

import (
	"strings"
	"testing"
)

func TestParseLockVerifyArgs(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		got, err := parseLockVerifyArgs(nil)
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "." || got.Format != "human" {
			t.Fatalf("unexpected defaults: %+v", got)
		}
	})

	t.Run("path and json format", func(t *testing.T) {
		got, err := parseLockVerifyArgs([]string{"./skill", "--format", "json"})
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "./skill" || got.Format != "json" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})

	t.Run("path and equals-format", func(t *testing.T) {
		got, err := parseLockVerifyArgs([]string{"./skill", "--format=json"})
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "./skill" || got.Format != "json" {
			t.Fatalf("unexpected parse result for equals-format: %+v", got)
		}
	})

	t.Run("path and sarif format", func(t *testing.T) {
		got, err := parseLockVerifyArgs([]string{"./skill", "--format", "sarif"})
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "./skill" || got.Format != "sarif" {
			t.Fatalf("unexpected parse result for sarif: %+v", got)
		}
	})

	t.Run("path and compact format", func(t *testing.T) {
		got, err := parseLockVerifyArgs([]string{"./skill", "--format", "compact"})
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "./skill" || got.Format != "compact" {
			t.Fatalf("unexpected parse result for compact: %+v", got)
		}
	})

	t.Run("errors", func(t *testing.T) {
		_, err := parseLockVerifyArgs([]string{"--format"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --format") {
			t.Fatalf("expected format value error, got %v", err)
		}
		_, err = parseLockVerifyArgs([]string{"./a", "./b"})
		if err == nil || !strings.Contains(err.Error(), "at most one path") {
			t.Fatalf("expected too many paths error, got %v", err)
		}
		_, err = parseLockVerifyArgs([]string{"--bad"})
		if err == nil || !strings.Contains(err.Error(), "unknown lock verify option") {
			t.Fatalf("expected unknown option error, got %v", err)
		}
		_, err = parseLockVerifyArgs([]string{"--format", "xml"})
		if err == nil || !strings.Contains(err.Error(), "unsupported lock verify format") {
			t.Fatalf("expected unsupported format error, got %v", err)
		}
	})

	t.Run("json-request and path extraction helpers", func(t *testing.T) {
		if !argsRequestFormat([]string{"--format", "json"}, "json") {
			t.Fatal("argsRequestFormat json should detect --format json")
		}
		if !argsRequestFormat([]string{"--format=json"}, "json") {
			t.Fatal("argsRequestFormat json should detect --format=json")
		}
		if argsRequestFormat([]string{"--format", "human"}, "json") {
			t.Fatal("argsRequestFormat json should be false for human format")
		}
		if !argsRequestFormat([]string{"--format", "sarif"}, "sarif") {
			t.Fatal("argsRequestFormat sarif should detect --format sarif")
		}
		if !argsRequestFormat([]string{"--format=sarif"}, "sarif") {
			t.Fatal("argsRequestFormat sarif should detect --format=sarif")
		}
		if argsRequestFormat([]string{"--format", "human"}, "sarif") {
			t.Fatal("argsRequestFormat sarif should be false for human format")
		}

		if got := extractLockVerifyPathArg([]string{"./skill", "--format", "json"}); got != "./skill" {
			t.Fatalf("extractLockVerifyPathArg() = %q, want ./skill", got)
		}
		if got := extractLockVerifyPathArg([]string{"--format=json", "./skill"}); got != "./skill" {
			t.Fatalf("extractLockVerifyPathArg(equals) = %q, want ./skill", got)
		}
		if got := extractLockVerifyPathArg([]string{"--bad", "--format", "json"}); got != "." {
			t.Fatalf("extractLockVerifyPathArg(default) = %q, want .", got)
		}
	})
}
