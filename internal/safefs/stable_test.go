package safefs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type errorStatter struct{ err error }

func (s errorStatter) Stat() (os.FileInfo, error) { return nil, s.err }

func TestSentinelCheckCurrent(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first.txt")
	if err := os.WriteFile(first, []byte("one"), 0o644); err != nil {
		t.Fatalf("write first: %v", err)
	}
	second := filepath.Join(root, "second.txt")
	if err := os.WriteFile(second, []byte("two"), 0o644); err != nil {
		t.Fatalf("write second: %v", err)
	}
	firstInfo, err := os.Lstat(first)
	if err != nil {
		t.Fatalf("lstat first: %v", err)
	}
	secondInfo, err := os.Lstat(second)
	if err != nil {
		t.Fatalf("lstat second: %v", err)
	}

	changedErr := errors.New("changed")
	s := Sentinel{
		Previous: firstInfo,
		Path:     first,
		ChangedError: func(string) error {
			return changedErr
		},
	}
	if err := s.CheckCurrent(firstInfo); err != nil {
		t.Fatalf("same file should pass: %v", err)
	}
	if err := s.CheckCurrent(secondInfo); !errors.Is(err, changedErr) {
		t.Fatalf("expected changed error, got %v", err)
	}

	if err := (Sentinel{Previous: firstInfo, Path: first}).CheckCurrent(secondInfo); err != nil {
		t.Fatalf("changed file without callback should pass, got %v", err)
	}
}

func TestSentinelCheckOpened(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "data.txt")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat data: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open data: %v", err)
	}
	defer f.Close()

	s := Sentinel{Previous: info, Path: path}
	if err := s.CheckOpened(f); err != nil {
		t.Fatalf("same opened file should pass: %v", err)
	}

	statErr := errors.New("stat failed")
	s.StatError = func(string) error { return statErr }
	if err := s.CheckOpened(errorStatter{err: errors.New("raw")}); !errors.Is(err, statErr) {
		t.Fatalf("expected stat callback error, got %v", err)
	}
	rawErr := errors.New("raw")
	if err := (Sentinel{Previous: info, Path: path}).CheckOpened(errorStatter{err: rawErr}); !errors.Is(err, rawErr) {
		t.Fatalf("expected raw stat error, got %v", err)
	}
}

func TestRootCheckValidate(t *testing.T) {
	t.Run("accepts directory", func(t *testing.T) {
		if err := (RootCheck{Root: t.TempDir(), Label: "input", SymlinkRuleID: "SYM", SpecialRuleID: "SPECIAL"}).Validate(); err != nil {
			t.Fatalf("directory should pass: %v", err)
		}
	})

	t.Run("rejects regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file.txt")
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		err := (RootCheck{Root: path, Label: "input", SymlinkRuleID: "SYM", SpecialRuleID: "SPECIAL"}).Validate()
		if err == nil || !strings.Contains(err.Error(), "SPECIAL: input root must be a directory") {
			t.Fatalf("expected special-file error, got %v", err)
		}
	})

	t.Run("rejects symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatalf("mkdir target: %v", err)
		}
		link := filepath.Join(root, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink target: %v", err)
		}
		err := (RootCheck{Root: link, Label: "input", SymlinkRuleID: "SYM", SpecialRuleID: "SPECIAL"}).Validate()
		if err == nil || !strings.Contains(err.Error(), "SYM: input root must not be a symlink") {
			t.Fatalf("expected symlink error, got %v", err)
		}
	})

	t.Run("wraps stat errors with prefix", func(t *testing.T) {
		err := (RootCheck{Root: filepath.Join(t.TempDir(), "missing"), Label: "input", StatErrorPrefix: "failed to stat input root"}).Validate()
		if err == nil || !strings.Contains(err.Error(), "failed to stat input root") {
			t.Fatalf("expected stat prefix, got %v", err)
		}
	})

	t.Run("returns raw stat errors without prefix", func(t *testing.T) {
		err := (RootCheck{Root: filepath.Join(t.TempDir(), "missing")}).Validate()
		if err == nil || !os.IsNotExist(err) {
			t.Fatalf("expected raw stat error, got %v", err)
		}
	})
}
