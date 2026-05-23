package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

type fetchArgs struct {
	Source string
	Out    string
	Format string
}

type fetchReport struct {
	SchemaVersion string `json:"schema_version"`
	Source        source `json:"source"`
	Output        string `json:"output"`
	Decision      string `json:"decision"`
	Note          string `json:"note"`
}

var (
	fetchSkillAtomicFunc = fetchSkillAtomic
	writeSourceMetaFunc  = writeSourceMetadata
)

func runFetch(args []string, stdout io.Writer, stderr io.Writer) int {
	parsed, err := parseFetchArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return 1
	}

	sourceKind := detectSourceKind(parsed.Source)
	if sourceKind != "github-source" {
		_, _ = fmt.Fprintln(stderr, "fetch currently supports github sources only")
		return 1
	}

	spec, err := srcpkg.ParseGitHubSource(parsed.Source)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid github source: %v\n", err)
		return 1
	}
	if !srcpkg.IsCommitPinnedRef(spec.Ref) {
		_, _ = fmt.Fprintln(stderr, "fetch requires a commit-pinned ref (e.g. @8f3c2d1a4b5c6d7e8f901234567890abcdef1234)")
		return 1
	}

	skillRoot, cleanup, err := fetchGitHubSkill(spec)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	meta, err := validateSkillFrontmatter(filepath.Join(skillRoot, "SKILL.md"))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	outRoot := filepath.Clean(parsed.Out)
	if err := os.MkdirAll(outRoot, 0o755); err != nil {
		_, _ = fmt.Fprintf(stderr, "failed to prepare fetch output root: %v\n", err)
		return 1
	}

	dest, err := fetchSkillAtomicFunc(skillRoot, outRoot, meta.Name)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}
	_, rootHash, err := buildFileDigestsFiltered(dest, map[string]struct{}{
		sourceMetadataFile: {},
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}
	if err := writeSourceMetaFunc(dest, sourceMetadata{
		Schema:          "gokui.source/v1",
		SourceInput:     parsed.Source,
		SourceKind:      "github-source",
		ResolvedRef:     spec.Ref,
		FetchedAt:       time.Now().UTC().Format(time.RFC3339),
		SkillRootSHA256: rootHash,
	}); err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	report := fetchReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: parsed.Source,
			Kind:  sourceKind,
		},
		Output:   dest,
		Decision: "FETCHED",
		Note:     "pre-release fetch materializes commit-pinned github source into quarantine",
	}

	if parsed.Format == "json" {
		out, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		return 0
	}

	_, _ = fmt.Fprintln(stdout, "gokui fetch report (pre-release)")
	_, _ = fmt.Fprintf(stdout, "source: %s (%s)\n", report.Source.Input, report.Source.Kind)
	_, _ = fmt.Fprintf(stdout, "decision: %s\n", report.Decision)
	_, _ = fmt.Fprintf(stdout, "output: %s\n", report.Output)
	return 0
}

func parseFetchArgs(args []string) (fetchArgs, error) {
	out := fetchArgs{Format: "human"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--out":
			if i+1 >= len(args) {
				return fetchArgs{}, fmt.Errorf("missing value for --out")
			}
			out.Out = args[i+1]
			i++
		case strings.HasPrefix(arg, "--out="):
			out.Out = strings.TrimPrefix(arg, "--out=")
		case arg == "--format":
			if i+1 >= len(args) {
				return fetchArgs{}, fmt.Errorf("missing value for --format")
			}
			out.Format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			out.Format = strings.TrimPrefix(arg, "--format=")
		case strings.HasPrefix(arg, "-"):
			return fetchArgs{}, fmt.Errorf("unknown fetch option: %s", arg)
		default:
			if out.Source != "" {
				return fetchArgs{}, fmt.Errorf("fetch accepts exactly one source")
			}
			out.Source = arg
		}
	}

	if out.Source == "" {
		return fetchArgs{}, fmt.Errorf("fetch source is required")
	}
	if strings.TrimSpace(out.Out) == "" {
		return fetchArgs{}, fmt.Errorf("fetch output root is required (--out)")
	}
	if out.Format != "human" && out.Format != "json" {
		return fetchArgs{}, fmt.Errorf("unsupported fetch format: %s", out.Format)
	}
	return out, nil
}

func fetchSkillAtomic(skillRoot string, outRoot string, skillName string) (string, error) {
	finalPath := filepath.Join(outRoot, skillName)
	if _, err := os.Stat(finalPath); err == nil {
		return "", fmt.Errorf("fetch output already contains skill: %s", finalPath)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to check fetch output target: %w", err)
	}

	stagingRoot, err := os.MkdirTemp(outRoot, ".gokui-fetch-*")
	if err != nil {
		return "", fmt.Errorf("failed to create fetch staging directory: %w", err)
	}
	defer os.RemoveAll(stagingRoot)

	stagedSkill := filepath.Join(stagingRoot, skillName)
	if err := copyTreeNormalized(skillRoot, stagedSkill); err != nil {
		return "", err
	}
	if err := os.Rename(stagedSkill, finalPath); err != nil {
		return "", fmt.Errorf("failed to finalize fetch: %w", err)
	}
	return finalPath, nil
}
