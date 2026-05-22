package app

import (
	"fmt"
	"io"
	"strings"
)

type Config struct {
	Version string
	Commit  string
	Date    string
}

func BuildVersionString(cfg Config) string {
	version := cfg.Version
	if version == "" {
		version = "dev"
	}

	commit := cfg.Commit
	if commit == "" {
		commit = "none"
	}

	date := cfg.Date
	if date == "" {
		date = "unknown"
	}

	return fmt.Sprintf("%s (%s, %s)", version, commit, date)
}

func Run(args []string, stdout io.Writer, stderr io.Writer, cfg Config) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, usage())
		return 1
	}

	if len(args) == 1 && args[0] == "version" {
		_, _ = fmt.Fprintln(stdout, BuildVersionString(cfg))
		return 0
	}

	switch args[0] {
	case "inspect", "install", "update":
		return notImplemented(stderr, args[0])
	case "lock":
		if len(args) >= 2 && args[1] == "verify" {
			return notImplemented(stderr, "lock verify")
		}
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s\n", strings.Join(args, " "), usage())
		return 1
	}

	_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s\n", strings.Join(args, " "), usage())
	return 1
}

func usage() string {
	return strings.TrimSpace(`
gokui is pre-release software.

usage:
  gokui version
  gokui inspect <local-dir|zip|github-source>
  gokui install <source> --target codex --profile strict
  gokui update --dry-run
  gokui lock verify`)
}

func notImplemented(stderr io.Writer, command string) int {
	_, _ = fmt.Fprintf(stderr, "gokui is pre-release: command not implemented yet: %s\n", command)
	return 2
}
