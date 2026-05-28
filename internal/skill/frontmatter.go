package skill

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/limitio"
	"github.com/watany-dev/gokui/internal/safefs"
	yaml "go.yaml.in/yaml/v4"
)

const (
	RuleFrontmatterTooLarge      = "SKILL_FRONTMATTER_TOO_LARGE"
	RuleFrontmatterSymlink       = "SKILL_FRONTMATTER_SYMLINK_DETECTED"
	RuleFrontmatterSpecialFile   = "SKILL_FRONTMATTER_SPECIAL_FILE"
	RuleFrontmatterInvalidUTF8   = "SKILL_FRONTMATTER_INVALID_UTF8"
	RuleFrontmatterSourceChanged = "SKILL_FRONTMATTER_SOURCE_CHANGED_DURING_READ"
	RuleDescriptionToolInjection = "DESCRIPTION_TOOL_INJECTION"
)

var (
	namePattern                = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	descriptionURLPattern      = regexp.MustCompile(`(?i)\b(?:https?://|ftp://|www\.)\S+`)
	descriptionCommandPattern  = regexp.MustCompile(`(?i)\b(run|execute|exec|invoke|call|use)\b.{0,30}\b(bash|sh|zsh|pwsh|powershell|python|node|npm|npx|uvx|go|curl|wget|terminal|command)\b`)
	descriptionOverridePattern = regexp.MustCompile(`(?i)\b(ignore|override|bypass)\b.{0,40}\b(previous|prior|system|higher|earlier)\b.{0,20}\b(instruction|instructions|prompt|prompts)\b`)
)

// Frontmatter contains the required metadata from a skill bundle SKILL.md.
type Frontmatter struct {
	Name        string
	Description string
}

func ValidateFrontmatter(skillPath string, maxBytes int64) (Frontmatter, error) {
	info, statErr := os.Lstat(skillPath)
	if statErr != nil {
		return Frontmatter{}, fmt.Errorf("failed to read SKILL.md: %s", skillPath)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Frontmatter{}, fmt.Errorf("%s: SKILL.md must not be a symlink: %s", RuleFrontmatterSymlink, skillPath)
	}
	if !info.Mode().IsRegular() {
		return Frontmatter{}, fmt.Errorf("%s: SKILL.md must be a regular file: %s", RuleFrontmatterSpecialFile, skillPath)
	}
	f, err := os.Open(skillPath)
	if err != nil {
		return Frontmatter{}, fmt.Errorf("failed to read SKILL.md: %s", skillPath)
	}
	defer f.Close()
	currentInfo, statErr := f.Stat()
	if statErr != nil {
		return Frontmatter{}, fmt.Errorf("failed to read SKILL.md: %s", skillPath)
	}
	if err := EnsureFrontmatterStableFile(info, currentInfo, skillPath); err != nil {
		return Frontmatter{}, err
	}
	var content bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&content, f, maxBytes); err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			return Frontmatter{}, fmt.Errorf("%s: SKILL.md exceeds size limit: %s", RuleFrontmatterTooLarge, skillPath)
		}
		return Frontmatter{}, fmt.Errorf("failed to read SKILL.md: %s", skillPath)
	}
	if !utf8.Valid(content.Bytes()) {
		return Frontmatter{}, fmt.Errorf("%s: SKILL.md must be valid UTF-8: %s", RuleFrontmatterInvalidUTF8, skillPath)
	}

	text := strings.ReplaceAll(content.String(), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || lines[0] != "---" {
		return Frontmatter{}, fmt.Errorf("SKILL.md must start with YAML frontmatter: %s", skillPath)
	}

	end := -1
	for i := 1; i < len(lines); i++ {
		if lines[i] == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return Frontmatter{}, fmt.Errorf("SKILL.md frontmatter is not closed: %s", skillPath)
	}

	frontmatter := strings.Join(lines[1:end], "\n")
	root, err := ParseFrontmatterYAML(frontmatter)
	if err != nil {
		return Frontmatter{}, fmt.Errorf("invalid SKILL.md frontmatter YAML: %s", skillPath)
	}

	if err := ValidateFrontmatterYAML(root); err != nil {
		return Frontmatter{}, err
	}

	if err := ValidateNoDuplicateKeys(root); err != nil {
		return Frontmatter{}, err
	}

	name, okName := FrontmatterStringField(root, "name")
	description, okDescription := FrontmatterStringField(root, "description")
	if !okName || !okDescription || strings.TrimSpace(name) == "" || strings.TrimSpace(description) == "" {
		return Frontmatter{}, fmt.Errorf("frontmatter must include non-empty string fields: name and description")
	}

	if err := ValidateName(name); err != nil {
		return Frontmatter{}, err
	}
	if err := ValidateDescription(description); err != nil {
		return Frontmatter{}, err
	}

	return Frontmatter{
		Name:        name,
		Description: description,
	}, nil
}

func EnsureFrontmatterStableFile(previous os.FileInfo, current os.FileInfo, skillPath string) error {
	return safefs.Sentinel{
		Previous: previous,
		Path:     skillPath,
		ChangedError: func(path string) error {
			return fmt.Errorf("%s: SKILL.md changed during read: %s", RuleFrontmatterSourceChanged, path)
		},
	}.CheckCurrent(current)
}

func ParseFrontmatterYAML(frontmatter string) (*yaml.Node, error) {
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

func ValidateFrontmatterYAML(node *yaml.Node) error {
	if node == nil {
		return fmt.Errorf("frontmatter root must be a YAML mapping")
	}

	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("YAML aliases are not allowed in SKILL.md frontmatter")
	}
	if node.Anchor != "" {
		return fmt.Errorf("YAML anchors are not allowed in SKILL.md frontmatter")
	}
	if IsCustomYAMLTag(node.Tag) {
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
		if err := ValidateFrontmatterYAML(child); err != nil {
			return err
		}
	}

	return nil
}

func IsCustomYAMLTag(tag string) bool {
	if tag == "" {
		return false
	}
	return strings.HasPrefix(tag, "!") && !strings.HasPrefix(tag, "!!")
}

func ValidateNoDuplicateKeys(root *yaml.Node) error {
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

func FrontmatterStringField(root *yaml.Node, field string) (string, bool) {
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

func ValidateName(name string) error {
	if len(name) > 64 {
		return fmt.Errorf("frontmatter name is invalid: must be at most 64 characters")
	}
	if !namePattern.MatchString(name) {
		return fmt.Errorf("frontmatter name is invalid: expected lowercase ASCII letters, digits, and single hyphens")
	}
	return nil
}

func ValidateDescription(description string) error {
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
		return fmt.Errorf("%s: description must not contain prompt override language", RuleDescriptionToolInjection)
	}
	if descriptionCommandPattern.MatchString(trimmed) {
		return fmt.Errorf("%s: description must not include tool or command execution instructions", RuleDescriptionToolInjection)
	}
	return nil
}
