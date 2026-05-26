package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

const (
	envPolicyPath    = "GOKUI_POLICY_PATH"
	maxPolicyBytes   = 1_000_000
	defaultPolicyRel = ".config/gokui/policy.toml"
	repoPolicyFile   = ".gokui-policy.toml"
)

// Config is the user policy contract loaded from policy.toml.
type Config struct {
	DefaultProfile string                   `toml:"default_profile"`
	Overrides      OverridesConfig          `toml:"overrides"`
	Profiles       map[string]ProfileConfig `toml:"profiles"`
}

type OverridesConfig struct {
	Enabled        bool     `toml:"enabled"`
	AllowedRuleIDs []string `toml:"allowed_rule_ids"`
}

type ProfileConfig struct {
	RejectSeverities []string `toml:"reject_severities"`
}

// LoadUserPolicy loads a user policy from GOKUI_POLICY_PATH or
// ~/.config/gokui/policy.toml. If no file exists, found=false and err=nil.
func LoadUserPolicy() (cfg Config, found bool, err error) {
	path, err := resolvePolicyPath()
	if err != nil {
		return Config{}, false, err
	}
	return loadPolicyFile(path)
}

// LoadRepositoryPolicy walks up from startPath and loads the nearest
// .gokui-policy.toml file. If no file exists in any ancestor directory,
// found=false and err=nil.
func LoadRepositoryPolicy(startPath string) (cfg Config, found bool, err error) {
	startDir, err := resolveRepositoryPolicyStartDir(startPath)
	if err != nil {
		return Config{}, false, err
	}

	dir := startDir
	for {
		candidate := filepath.Join(dir, repoPolicyFile)
		cfg, found, err := loadPolicyFile(candidate)
		if err != nil {
			return Config{}, false, err
		}
		if found {
			return cfg, true, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return Config{}, false, nil
		}
		dir = parent
	}
}

func resolveRepositoryPolicyStartDir(startPath string) (string, error) {
	cleaned := filepath.Clean(startPath)
	if strings.TrimSpace(cleaned) == "" {
		return "", fmt.Errorf("failed to resolve repository policy start path: empty path")
	}
	if cleaned == "." {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to resolve repository policy start path: %w", err)
		}
		cleaned = cwd
	}
	info, err := os.Stat(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return cleaned, nil
		}
		return "", fmt.Errorf("failed to resolve repository policy start path: %w", err)
	}
	if info.IsDir() {
		return cleaned, nil
	}
	return filepath.Dir(cleaned), nil
}

func loadPolicyFile(path string) (cfg Config, found bool, err error) {
	cfg.Overrides.Enabled = true
	if err := rejectSymlinkPath(path); err != nil {
		return Config{}, false, err
	}

	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, false, nil
		}
		return Config{}, false, fmt.Errorf("failed to read policy file metadata: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, false, fmt.Errorf("policy file must be a regular file: %s", path)
	}
	if info.Size() > maxPolicyBytes {
		return Config{}, false, fmt.Errorf("policy file exceeds max size (%d bytes): %s", maxPolicyBytes, path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, false, fmt.Errorf("failed to read policy file: %w", err)
	}
	if !utf8.Valid(raw) {
		return Config{}, false, fmt.Errorf("policy file must be valid UTF-8: %s", path)
	}

	meta, err := toml.Decode(string(raw), &cfg)
	if err != nil {
		return Config{}, false, fmt.Errorf("failed to parse policy file: %w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return Config{}, false, fmt.Errorf("unknown policy keys: %v", undecoded)
	}
	cfg.DefaultProfile = strings.TrimSpace(strings.ToLower(cfg.DefaultProfile))
	cfg.Overrides.AllowedRuleIDs = normalizeOverrideRuleIDs(cfg.Overrides.AllowedRuleIDs)
	cfg.Profiles = normalizeProfileConfigs(cfg.Profiles)
	return cfg, true, nil
}

func normalizeOverrideRuleIDs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, id := range in {
		clean := strings.ToUpper(strings.TrimSpace(id))
		if clean == "" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}

func normalizeProfileConfigs(in map[string]ProfileConfig) map[string]ProfileConfig {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]ProfileConfig, len(in))
	for profile, cfg := range in {
		key := strings.ToLower(strings.TrimSpace(profile))
		if key == "" {
			continue
		}
		cfg.RejectSeverities = normalizeSeverities(cfg.RejectSeverities)
		out[key] = cfg
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeSeverities(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, sev := range in {
		clean := strings.ToLower(strings.TrimSpace(sev))
		if clean == "" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}

func resolvePolicyPath() (string, error) {
	if override := strings.TrimSpace(os.Getenv(envPolicyPath)); override != "" {
		return filepath.Clean(override), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve home directory for policy path: %w", err)
	}
	return filepath.Join(home, defaultPolicyRel), nil
}

func rejectSymlinkPath(path string) error {
	for _, candidate := range symlinkCheckCandidates(path) {
		info, err := os.Lstat(candidate)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
				return nil
			}
			return fmt.Errorf("failed to validate policy path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if isRootLevelPathComponent(candidate) {
				continue
			}
			return fmt.Errorf("policy path must not contain symlink component: %s", candidate)
		}
	}
	return nil
}

func symlinkCheckCandidates(path string) []string {
	cleanPath := filepath.Clean(path)
	candidates := []string{cleanPath}

	for current := cleanPath; ; {
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		candidates = append(candidates, parent)
		current = parent
	}

	for i, j := 0, len(candidates)-1; i < j; i, j = i+1, j-1 {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}

	return candidates
}

func isRootLevelPathComponent(path string) bool {
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) {
		return false
	}
	parent := filepath.Dir(cleanPath)
	if parent == cleanPath {
		return false
	}
	return filepath.Dir(parent) == parent
}
