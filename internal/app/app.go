package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Version string
	Commit  string
	Date    string
}

type inspectReport struct {
	SchemaVersion string   `json:"schema_version"`
	PreRelease    bool     `json:"pre_release"`
	Source        source   `json:"source"`
	Decision      string   `json:"decision"`
	Findings      []string `json:"findings"`
	Note          string   `json:"note"`
}

type source struct {
	Input string `json:"input"`
	Kind  string `json:"kind"`
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
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "install", "update":
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

func runInspect(args []string, stdout io.Writer, stderr io.Writer) int {
	input, format, err := parseInspectArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return 1
	}

	sourceKind := detectSourceKind(input)

	if sourceKind != "github-source" {
		if _, statErr := os.Stat(input); statErr != nil {
			_, _ = fmt.Fprintf(stderr, "inspect source not found: %s\n", input)
			return 1
		}
	}
	if sourceKind == "local-dir" {
		if validateErr := validateLocalDirInspectSource(input); validateErr != nil {
			_, _ = fmt.Fprintln(stderr, validateErr.Error())
			return 1
		}
	}

	report := inspectReport{
		SchemaVersion: "0.1.0-draft",
		PreRelease:    true,
		Source: source{
			Input: input,
			Kind:  sourceKind,
		},
		Decision: "PRE_RELEASE_STUB",
		Findings: []string{},
		Note:     "inspect pipeline is not implemented yet",
	}

	if format == "json" {
		out, marshalErr := json.MarshalIndent(report, "", "  ")
		if marshalErr != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render inspect report")
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		return 0
	}

	_, _ = fmt.Fprintln(stdout, "gokui is pre-release: inspect pipeline is not implemented yet")
	_, _ = fmt.Fprintf(stdout, "source: %s (%s)\n", report.Source.Input, report.Source.Kind)
	return 0
}

func parseInspectArgs(args []string) (input string, format string, err error) {
	format = "human"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--format" {
			if i+1 >= len(args) {
				return "", "", fmt.Errorf("missing value for --format")
			}
			format = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return "", "", fmt.Errorf("unknown inspect option: %s", arg)
		}
		if input != "" {
			return "", "", fmt.Errorf("inspect accepts exactly one source")
		}
		input = arg
	}

	if input == "" {
		return "", "", fmt.Errorf("inspect source is required")
	}
	if format != "human" && format != "json" {
		return "", "", fmt.Errorf("unsupported inspect format: %s", format)
	}
	return input, format, nil
}

func detectSourceKind(input string) string {
	lower := strings.ToLower(input)
	switch {
	case strings.HasPrefix(input, "github:"):
		return "github-source"
	case strings.HasSuffix(lower, ".zip"):
		return "zip"
	case strings.HasSuffix(lower, ".tar"), strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "tar"
	default:
		return "local-dir"
	}
}

func validateLocalDirInspectSource(input string) error {
	info, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("inspect source not found: %s", input)
	}
	if !info.IsDir() {
		return fmt.Errorf("inspect local source must be a directory: %s", input)
	}

	skillPath := filepath.Join(input, "SKILL.md")
	skillInfo, skillErr := os.Stat(skillPath)
	if skillErr != nil || skillInfo.IsDir() {
		return fmt.Errorf("inspect local dir must contain SKILL.md at root: %s", input)
	}
	return nil
}
