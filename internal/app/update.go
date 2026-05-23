package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

var updateURLPattern = regexp.MustCompile(`https?://[^\s<>"')\]]+`)

type updateArgs struct {
	DryRun bool
	Target string
	Format string
}

type updateReport struct {
	SchemaVersion string            `json:"schema_version"`
	Target        string            `json:"target"`
	DryRun        bool              `json:"dry_run"`
	Skills        []updateSkillItem `json:"skills"`
	Summary       updateSummary     `json:"summary"`
	Note          string            `json:"note"`
}

type updateSkillItem struct {
	Name               string           `json:"name"`
	Path               string           `json:"path"`
	Source             source           `json:"source"`
	Status             string           `json:"status"`
	Decision           string           `json:"decision"`
	Diff               updateDiff       `json:"diff"`
	Risk               updateRisk       `json:"risk"`
	NewURLs            []string         `json:"new_urls"`
	NewExecutableFiles []string         `json:"new_executable_files"`
	Findings           []inspectFinding `json:"findings"`
	Message            string           `json:"message"`
}

type updateDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Changed []string `json:"changed"`
}

type updateRisk struct {
	Previous lockFindingSummary `json:"previous"`
	Current  lockFindingSummary `json:"current"`
	Delta    lockFindingSummary `json:"delta"`
}

type updateSummary struct {
	Total    int `json:"total"`
	UpToDate int `json:"up_to_date"`
	Changed  int `json:"changed"`
	Rejected int `json:"rejected"`
	Errors   int `json:"errors"`
	Skipped  int `json:"skipped"`
}

func runUpdate(args []string, stdout io.Writer, stderr io.Writer) int {
	parsed, err := parseUpdateArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return 1
	}

	targetRoot, err := resolveInstallTarget(parsed.Target)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	report, err := buildUpdateReport(targetRoot)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	if parsed.Format == "json" {
		out, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
	} else {
		_, _ = fmt.Fprintln(stdout, "gokui update report (pre-release)")
		_, _ = fmt.Fprintf(stdout, "target: %s\n", report.Target)
		_, _ = fmt.Fprintf(stdout, "skills: %d\n", report.Summary.Total)
		for _, skill := range report.Skills {
			decision := skill.Decision
			if decision == "" {
				decision = "-"
			}
			_, _ = fmt.Fprintf(stdout, "- %s: %s (decision=%s)\n", skill.Name, skill.Status, decision)
			_, _ = fmt.Fprintf(stdout, "  diff added=%d removed=%d changed=%d\n", len(skill.Diff.Added), len(skill.Diff.Removed), len(skill.Diff.Changed))
			_, _ = fmt.Fprintf(stdout, "  new urls=%d new executables=%d\n", len(skill.NewURLs), len(skill.NewExecutableFiles))
			_, _ = fmt.Fprintf(stdout, "  note: %s\n", skill.Message)
		}
		_, _ = fmt.Fprintf(stdout, "summary: up_to_date=%d changed=%d rejected=%d skipped=%d errors=%d\n",
			report.Summary.UpToDate,
			report.Summary.Changed,
			report.Summary.Rejected,
			report.Summary.Skipped,
			report.Summary.Errors,
		)
	}

	if report.Summary.Errors > 0 {
		return 1
	}
	if report.Summary.Rejected > 0 {
		return 2
	}
	return 0
}

func parseUpdateArgs(args []string) (updateArgs, error) {
	out := updateArgs{
		Target: "codex",
		Format: "human",
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--dry-run":
			out.DryRun = true
		case arg == "--target":
			if i+1 >= len(args) {
				return updateArgs{}, fmt.Errorf("missing value for --target")
			}
			out.Target = args[i+1]
			i++
		case strings.HasPrefix(arg, "--target="):
			out.Target = strings.TrimPrefix(arg, "--target=")
		case arg == "--format":
			if i+1 >= len(args) {
				return updateArgs{}, fmt.Errorf("missing value for --format")
			}
			out.Format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			out.Format = strings.TrimPrefix(arg, "--format=")
		case strings.HasPrefix(arg, "-"):
			return updateArgs{}, fmt.Errorf("unknown update option: %s", arg)
		default:
			return updateArgs{}, fmt.Errorf("update does not accept positional arguments: %s", arg)
		}
	}

	if !out.DryRun {
		return updateArgs{}, fmt.Errorf("update currently requires --dry-run")
	}
	if out.Format != "human" && out.Format != "json" {
		return updateArgs{}, fmt.Errorf("unsupported update format: %s", out.Format)
	}
	return out, nil
}

func buildUpdateReport(targetRoot string) (updateReport, error) {
	cleanTarget := filepath.Clean(targetRoot)
	entries, err := os.ReadDir(cleanTarget)
	if err != nil {
		return updateReport{}, fmt.Errorf("failed to read update target: %s", cleanTarget)
	}

	skills := make([]updateSkillItem, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		skillPath := filepath.Join(cleanTarget, entry.Name())
		item := updateSkillItem{
			Name: entry.Name(),
			Path: skillPath,
			Diff: updateDiff{
				Added:   []string{},
				Removed: []string{},
				Changed: []string{},
			},
			NewURLs:            []string{},
			NewExecutableFiles: []string{},
			Findings:           []inspectFinding{},
		}
		lockPath := filepath.Join(skillPath, installLockFile)
		lock, err := readInstallLock(lockPath)
		if err != nil {
			item.Status = "ERROR"
			item.Message = "missing or invalid lockfile"
			skills = append(skills, item)
			continue
		}
		item.Source = source{
			Input: lock.Source.Input,
			Kind:  lock.Source.Kind,
		}

		enriched, err := evaluateUpdateSkill(item, lock)
		if err != nil {
			item.Status = "ERROR"
			item.Message = err.Error()
			skills = append(skills, item)
			continue
		}
		skills = append(skills, enriched)
	}

	sort.Slice(skills, func(i, j int) bool {
		return skills[i].Name < skills[j].Name
	})

	summary := summarizeUpdateSkills(skills)
	return updateReport{
		SchemaVersion: reportSchemaVersion,
		Target:        cleanTarget,
		DryRun:        true,
		Skills:        skills,
		Summary:       summary,
		Note:          "pre-release update performs dry-run diff and policy re-evaluation",
	}, nil
}

func evaluateUpdateSkill(item updateSkillItem, lock installLock) (updateSkillItem, error) {
	kind := strings.TrimSpace(lock.Source.Kind)
	if kind == "" {
		kind = detectSourceKind(lock.Source.Input)
		item.Source.Kind = kind
	}
	if kind == "github-source" {
		spec, parseErr := srcpkg.ParseGitHubSource(lock.Source.Input)
		if parseErr != nil {
			item.Status = "ERROR"
			item.Message = fmt.Sprintf("invalid github source in lockfile: %v", parseErr)
			item.Risk = updateRisk{
				Previous: lock.Findings,
				Current:  lock.Findings,
			}
			return item, nil
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			item.Status = "REJECTED"
			item.Message = "floating github refs are not eligible for update; commit-pinned ref required"
			item.Risk = updateRisk{
				Previous: lock.Findings,
				Current:  lock.Findings,
			}
			return item, nil
		}
		if err := verifyInstalledSourceMetadata(item.Path, source{
			Input: lock.Source.Input,
			Kind:  kind,
		}); err != nil {
			item.Status = "ERROR"
			item.Message = err.Error()
			item.Risk = updateRisk{
				Previous: lock.Findings,
				Current:  lock.Findings,
			}
			return item, nil
		}
	}

	skillRoot, cleanup, err := preparePolicyEvaluationSource(lock.Source.Input, kind)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		if kind == "github-source" {
			message := err.Error()
			status := "ERROR"
			if strings.Contains(message, "commit-pinned ref") {
				status = "REJECTED"
			}
			item.Status = status
			item.Message = message
			item.Risk = updateRisk{
				Previous: lock.Findings,
				Current:  lock.Findings,
			}
			return item, nil
		}
		return updateSkillItem{}, err
	}

	findings, decision, err := evaluateSkill(skillRoot)
	if err != nil {
		return updateSkillItem{}, err
	}
	item.Findings = findings
	item.Decision = decision

	excludeMeta := map[string]struct{}{
		installReportFile: {},
		installLockFile:   {},
	}
	currentFiles, _, err := buildFileDigestsFiltered(skillRoot, excludeMeta)
	if err != nil {
		return updateSkillItem{}, err
	}
	previousFiles := filterLockFiles(lock.Skill.Files, excludeMeta)
	missing, changed, unexpected := diffLockFiles(previousFiles, currentFiles)
	item.Diff = updateDiff{
		Added:   unexpected,
		Removed: missing,
		Changed: changed,
	}

	previousURLs, err := collectURLs(item.Path)
	if err != nil {
		return updateSkillItem{}, err
	}
	currentURLs, err := collectURLs(skillRoot)
	if err != nil {
		return updateSkillItem{}, err
	}
	item.NewURLs = setDiff(currentURLs, previousURLs)

	previousExec, err := collectExecutableFiles(item.Path)
	if err != nil {
		return updateSkillItem{}, err
	}
	currentExec, err := collectExecutableFiles(skillRoot)
	if err != nil {
		return updateSkillItem{}, err
	}
	item.NewExecutableFiles = setDiff(currentExec, previousExec)

	currentRisk := summarizeFindingSeverities(findings)
	item.Risk = updateRisk{
		Previous: lock.Findings,
		Current:  currentRisk,
		Delta: lockFindingSummary{
			Critical: currentRisk.Critical - lock.Findings.Critical,
			High:     currentRisk.High - lock.Findings.High,
			Medium:   currentRisk.Medium - lock.Findings.Medium,
			Low:      currentRisk.Low - lock.Findings.Low,
		},
	}

	if decision == "REJECTED" {
		item.Status = "REJECTED"
		item.Message = "fresh policy evaluation rejected update source"
		return item, nil
	}

	changedContent := len(item.Diff.Added) > 0 || len(item.Diff.Removed) > 0 || len(item.Diff.Changed) > 0
	changedRisk := item.Risk.Delta.Critical != 0 || item.Risk.Delta.High != 0 || item.Risk.Delta.Medium != 0 || item.Risk.Delta.Low != 0
	changedSignals := len(item.NewURLs) > 0 || len(item.NewExecutableFiles) > 0
	if changedContent || changedRisk || changedSignals {
		item.Status = "CHANGED"
		item.Message = "update source differs from installed lock snapshot"
		return item, nil
	}

	item.Status = "UP_TO_DATE"
	item.Message = "no change detected against installed lock snapshot"
	return item, nil
}

func filterLockFiles(files []lockFileHash, exclude map[string]struct{}) []lockFileHash {
	out := make([]lockFileHash, 0, len(files))
	for _, file := range files {
		if _, skip := exclude[file.Path]; skip {
			continue
		}
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Path < out[j].Path
	})
	return out
}

func summarizeFindingSeverities(findings []inspectFinding) lockFindingSummary {
	out := lockFindingSummary{}
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			out.Critical++
		case "high":
			out.High++
		case "medium":
			out.Medium++
		case "low":
			out.Low++
		}
	}
	return out
}

func summarizeUpdateSkills(skills []updateSkillItem) updateSummary {
	out := updateSummary{Total: len(skills)}
	for _, skill := range skills {
		switch skill.Status {
		case "UP_TO_DATE":
			out.UpToDate++
		case "CHANGED":
			out.Changed++
		case "REJECTED":
			out.Rejected++
		case "SKIPPED":
			out.Skipped++
		default:
			out.Errors++
		}
	}
	return out
}

func collectURLs(root string) ([]string, error) {
	set := make(map[string]struct{}, 32)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !isMarkdownLikeFile(d.Name()) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file for URL scan: %w", err)
		}
		matches := updateURLPattern.FindAllString(string(content), -1)
		for _, m := range matches {
			set[m] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mapKeysSorted(set), nil
}

func collectExecutableFiles(root string) ([]string, error) {
	set := make(map[string]struct{}, 16)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o111 == 0 {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		set[filepath.ToSlash(rel)] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mapKeysSorted(set), nil
}

func mapKeysSorted(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func setDiff(current []string, previous []string) []string {
	previousSet := make(map[string]struct{}, len(previous))
	for _, v := range previous {
		previousSet[v] = struct{}{}
	}
	out := make([]string, 0, len(current))
	for _, v := range current {
		if _, ok := previousSet[v]; !ok {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func isMarkdownLikeFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".md") ||
		strings.HasSuffix(lower, ".markdown") ||
		strings.HasSuffix(lower, ".txt")
}
