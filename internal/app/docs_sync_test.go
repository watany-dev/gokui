package app

import (
	"os"
	"strings"
	"testing"
)

func TestCommandSetDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	agentsBytes, err := os.ReadFile("../../AGENTS.md")
	if err != nil {
		t.Fatalf("failed to read AGENTS.md: %v", err)
	}

	readme := string(readmeBytes)
	agents := string(agentsBytes)

	required := []string{
		"gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir>",
		"gokui inspect <local-dir|zip|github-source>",
		"gokui install <source> --target codex --profile strict",
		"gokui update --dry-run",
		"gokui lock verify",
	}

	for _, line := range required {
		if !strings.Contains(readme, line) {
			t.Fatalf("README.md missing documented command line: %q", line)
		}
		if !strings.Contains(agents, line) {
			t.Fatalf("AGENTS.md missing documented command line: %q", line)
		}
	}
}

func TestCLIUsageSyntaxDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	usageText := usage()

	required := []string{
		"gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir> [--format human|json]",
		"gokui inspect <local-dir|zip|github-source> [--format human|json]",
		"gokui install <source> --target codex --profile strict [--format human|json]",
		"gokui update --dry-run [--target codex|custom:/path] [--format human|json]",
		"gokui lock verify [path] [--format human|json]",
	}

	for _, line := range required {
		if !strings.Contains(readme, line) {
			t.Fatalf("README.md missing detailed CLI syntax: %q", line)
		}
		if !strings.Contains(usageText, line) {
			t.Fatalf("usage() missing detailed CLI syntax: %q", line)
		}
	}
}
