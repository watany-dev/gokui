package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/materialize"
	"github.com/watany-dev/gokui/internal/scan"
	srcpkg "github.com/watany-dev/gokui/internal/source"
	yaml "go.yaml.in/yaml/v4"
)

type Config struct {
	Version string
	Commit  string
	Date    string
}

type inspectReport struct {
	SchemaVersion string           `json:"schema_version"`
	PreRelease    bool             `json:"pre_release"`
	Source        source           `json:"source"`
	Decision      string           `json:"decision"`
	Findings      []inspectFinding `json:"findings"`
	Note          string           `json:"note"`
}

type source struct {
	Input string `json:"input"`
	Kind  string `json:"kind"`
}

type inspectFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Summary  string `json:"summary"`
}

type skillFrontmatter struct {
	Name        string
	Description string
}

var (
	skillNamePattern           = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	descriptionURLPattern      = regexp.MustCompile(`(?i)\b(?:https?://|ftp://|www\.)\S+`)
	descriptionCommandPattern  = regexp.MustCompile(`(?i)\b(run|execute|exec|invoke|call|use)\b.{0,30}\b(bash|sh|zsh|pwsh|powershell|python|node|npm|npx|uvx|go|curl|wget|terminal|command)\b`)
	descriptionOverridePattern = regexp.MustCompile(`(?i)\b(ignore|override|bypass)\b.{0,40}\b(previous|prior|system|higher|earlier)\b.{0,20}\b(instruction|instructions|prompt|prompts)\b`)
)

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
	case "fetch":
		return runFetch(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "install":
		return runInstall(args[1:], stdout, stderr)
	case "update":
		return runUpdate(args[1:], stdout, stderr)
	case "lock":
		if len(args) >= 2 && args[1] == "verify" {
			return runLockVerify(args[2:], stdout, stderr)
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
  gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir>
  gokui inspect <local-dir|zip|github-source>
  gokui install <source> --target codex --profile strict
  gokui update --dry-run
  gokui lock verify`)
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

	findings := make([]inspectFinding, 0)
	decision := "PASS"
	note := "pre-release inspect includes structural and markdown checks"
	if sourceKind == "github-source" {
		spec, parseErr := srcpkg.ParseGitHubSource(input)
		if parseErr != nil {
			_, _ = fmt.Fprintf(stderr, "invalid github source: %v\n", parseErr)
			return 1
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			decision = "PRE_RELEASE_STUB"
			note = "github source inspect is not implemented yet (floating ref accepted for inspect-only pre-release)"
		} else {
			skillRoot, cleanup, prepErr := preparePolicyEvaluationSource(input, sourceKind)
			if cleanup != nil {
				defer cleanup()
			}
			if prepErr != nil {
				_, _ = fmt.Fprintln(stderr, prepErr.Error())
				return 1
			}
			scanFindings, scanErr := scan.ScanSkillRoot(skillRoot)
			if scanErr != nil {
				_, _ = fmt.Fprintln(stderr, scanErr.Error())
				return 1
			}
			findings, decision = toInspectFindings(scanFindings)
			note = "pre-release inspect includes structural and markdown checks (github commit-pinned source)"
		}
	} else {
		skillRoot, cleanup, validateErr := prepareInspectSource(input, sourceKind)
		if cleanup != nil {
			defer cleanup()
		}
		if validateErr != nil {
			_, _ = fmt.Fprintln(stderr, validateErr.Error())
			return 1
		}
		scanFindings, scanErr := scan.ScanSkillRoot(skillRoot)
		if scanErr != nil {
			_, _ = fmt.Fprintln(stderr, scanErr.Error())
			return 1
		}
		findings, decision = toInspectFindings(scanFindings)
	}

	report := inspectReport{
		SchemaVersion: reportSchemaVersion,
		PreRelease:    true,
		Source: source{
			Input: input,
			Kind:  sourceKind,
		},
		Decision: decision,
		Findings: findings,
		Note:     note,
	}

	if format == "json" {
		out, marshalErr := json.MarshalIndent(report, "", "  ")
		if marshalErr != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render inspect report")
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == "REJECTED" {
			return 2
		}
		return 0
	}

	_, _ = fmt.Fprintln(stdout, "gokui inspect report (pre-release)")
	_, _ = fmt.Fprintf(stdout, "source: %s (%s)\n", report.Source.Input, report.Source.Kind)
	_, _ = fmt.Fprintf(stdout, "decision: %s\n", report.Decision)
	_, _ = fmt.Fprintf(stdout, "findings: %d\n", len(report.Findings))
	for _, finding := range report.Findings {
		_, _ = fmt.Fprintf(stdout, "- [%s] %s %s:%d %s\n", strings.ToUpper(finding.Severity), finding.ID, finding.File, finding.Line, finding.Summary)
	}
	if report.Decision == "REJECTED" {
		return 2
	}
	return 0
}

func toInspectFindings(scanFindings []scan.Finding) ([]inspectFinding, string) {
	findings := make([]inspectFinding, 0, len(scanFindings))
	decision := "PASS"
	for _, finding := range scanFindings {
		findings = append(findings, inspectFinding{
			ID:       finding.ID,
			Severity: finding.Severity,
			File:     finding.File,
			Line:     finding.Line,
			Summary:  finding.Summary,
		})
		if scan.IsRejectable(finding) {
			decision = "REJECTED"
		}
	}
	return findings, decision
}

func prepareInspectSource(input string, sourceKind string) (skillRoot string, cleanup func(), err error) {
	switch sourceKind {
	case "local-dir":
		if validateErr := validateLocalDirInspectSource(input); validateErr != nil {
			return "", nil, validateErr
		}
		return input, nil, nil
	case "zip", "tar":
		return prepareArchiveInspectSource(input, sourceKind)
	default:
		return "", nil, nil
	}
}

func prepareArchiveInspectSource(input string, sourceKind string) (string, func(), error) {
	tempRoot, err := os.MkdirTemp("", "gokui-inspect-archive-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create inspect quarantine: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(tempRoot)
	}

	extractDir := filepath.Join(tempRoot, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to prepare inspect extraction directory: %w", err)
	}

	limits := materialize.Limits{
		MaxFiles:      1000,
		MaxTotalBytes: 50 * 1024 * 1024,
		MaxFileBytes:  10 * 1024 * 1024,
	}
	if err := materialize.ExtractArchive(input, sourceKind, extractDir, limits); err != nil {
		cleanup()
		return "", nil, err
	}

	skillRoot, err := materialize.DetectSkillRoot(extractDir)
	if err != nil {
		cleanup()
		return "", nil, err
	}

	if err := validateLocalDirInspectSource(skillRoot); err != nil {
		cleanup()
		return "", nil, err
	}

	return skillRoot, cleanup, nil
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

	meta, err := validateSkillFrontmatter(skillPath)
	if err != nil {
		return err
	}

	dirName := filepath.Base(filepath.Clean(input))
	if dirName != meta.Name {
		return fmt.Errorf("frontmatter name must match directory name: name=%s dir=%s", meta.Name, dirName)
	}

	return nil
}

func validateSkillFrontmatter(skillPath string) (skillFrontmatter, error) {
	content, err := os.ReadFile(skillPath)
	if err != nil {
		return skillFrontmatter{}, fmt.Errorf("failed to read SKILL.md: %s", skillPath)
	}

	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || lines[0] != "---" {
		return skillFrontmatter{}, fmt.Errorf("SKILL.md must start with YAML frontmatter: %s", skillPath)
	}

	end := -1
	for i := 1; i < len(lines); i++ {
		if lines[i] == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return skillFrontmatter{}, fmt.Errorf("SKILL.md frontmatter is not closed: %s", skillPath)
	}

	frontmatter := strings.Join(lines[1:end], "\n")
	root, err := parseFrontmatterYAML(frontmatter)
	if err != nil {
		return skillFrontmatter{}, fmt.Errorf("invalid SKILL.md frontmatter YAML: %s", skillPath)
	}

	if err := validateFrontmatterYAML(root); err != nil {
		return skillFrontmatter{}, err
	}

	if err := validateNoDuplicateKeys(root); err != nil {
		return skillFrontmatter{}, err
	}

	name, okName := frontmatterStringField(root, "name")
	description, okDescription := frontmatterStringField(root, "description")
	if !okName || !okDescription || strings.TrimSpace(name) == "" || strings.TrimSpace(description) == "" {
		return skillFrontmatter{}, fmt.Errorf("frontmatter must include non-empty string fields: name and description")
	}

	if err := validateSkillName(name); err != nil {
		return skillFrontmatter{}, err
	}
	if err := validateSkillDescription(description); err != nil {
		return skillFrontmatter{}, err
	}

	return skillFrontmatter{
		Name:        name,
		Description: description,
	}, nil
}

func parseFrontmatterYAML(frontmatter string) (*yaml.Node, error) {
	var doc yaml.Node
	decoder := yaml.NewDecoder(strings.NewReader(frontmatter))
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}

	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("multiple YAML documents are not allowed")
	} else if err != io.EOF {
		return nil, err
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("frontmatter root must be a YAML mapping")
	}

	return doc.Content[0], nil
}

func validateFrontmatterYAML(node *yaml.Node) error {
	if node == nil {
		return fmt.Errorf("frontmatter root must be a YAML mapping")
	}

	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("YAML aliases are not allowed in SKILL.md frontmatter")
	}
	if node.Anchor != "" {
		return fmt.Errorf("YAML anchors are not allowed in SKILL.md frontmatter")
	}
	if isCustomYAMLTag(node.Tag) {
		return fmt.Errorf("custom YAML tags are not allowed in SKILL.md frontmatter")
	}

	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind == yaml.ScalarNode && key.Value == "<<" {
				return fmt.Errorf("YAML merge keys are not allowed in SKILL.md frontmatter")
			}
			if key.Tag == "!!merge" {
				return fmt.Errorf("YAML merge keys are not allowed in SKILL.md frontmatter")
			}
		}
	}

	for _, child := range node.Content {
		if err := validateFrontmatterYAML(child); err != nil {
			return err
		}
	}

	return nil
}

func isCustomYAMLTag(tag string) bool {
	if tag == "" {
		return false
	}
	return strings.HasPrefix(tag, "!") && !strings.HasPrefix(tag, "!!")
}

func validateNoDuplicateKeys(root *yaml.Node) error {
	seen := make(map[string]struct{}, len(root.Content)/2)
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i]
		if key.Kind != yaml.ScalarNode {
			continue
		}

		if _, ok := seen[key.Value]; ok {
			return fmt.Errorf("duplicate frontmatter key: %s", key.Value)
		}
		seen[key.Value] = struct{}{}
	}
	return nil
}

func frontmatterStringField(root *yaml.Node, field string) (string, bool) {
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i]
		value := root.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Value != field {
			continue
		}
		if value.Kind != yaml.ScalarNode {
			return "", false
		}
		return value.Value, true
	}
	return "", false
}

func validateSkillName(name string) error {
	if len(name) > 64 {
		return fmt.Errorf("frontmatter name is invalid: must be at most 64 characters")
	}
	if !skillNamePattern.MatchString(name) {
		return fmt.Errorf("frontmatter name is invalid: expected lowercase ASCII letters, digits, and single hyphens")
	}
	return nil
}

func validateSkillDescription(description string) error {
	trimmed := strings.TrimSpace(description)
	if trimmed == "" {
		return fmt.Errorf("frontmatter must include non-empty string fields: name and description")
	}
	if utf8.RuneCountInString(trimmed) > 1024 {
		return fmt.Errorf("description must be 1 to 1024 characters")
	}
	if descriptionURLPattern.MatchString(trimmed) {
		return fmt.Errorf("description must not contain URLs")
	}
	if strings.Contains(trimmed, "```") {
		return fmt.Errorf("description must not contain code fences")
	}
	if descriptionOverridePattern.MatchString(trimmed) {
		return fmt.Errorf("description must not contain prompt override language")
	}
	if descriptionCommandPattern.MatchString(trimmed) {
		return fmt.Errorf("description must not include tool or command execution instructions")
	}
	return nil
}
