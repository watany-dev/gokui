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
	if len(args) == 1 && args[0] == "version" {
		_, _ = fmt.Fprintln(stdout, BuildVersionString(cfg))
		return 0
	}

	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, usage())
		return 1
	}

	_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s\n", strings.Join(args, " "), usage())
	return 1
}

func usage() string {
	return "usage: gokui version"
}
