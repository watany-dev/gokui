package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	envPolicyPath    = "GOKUI_POLICY_PATH"
	maxPolicyBytes   = 1_000_000
	defaultPolicyRel = ".config/gokui/policy.toml"
)

// Config is the user policy contract loaded from policy.toml.
type Config struct {
	DefaultProfile string `toml:"default_profile"`
}

// LoadUserPolicy loads a user policy from GOKUI_POLICY_PATH or
// ~/.config/gokui/policy.toml. If no file exists, found=false and err=nil.
func LoadUserPolicy() (cfg Config, found bool, err error) {
	path, err := resolvePolicyPath()
	if err != nil {
		return Config{}, false, err
	}
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

	meta, err := toml.Decode(string(raw), &cfg)
	if err != nil {
		return Config{}, false, fmt.Errorf("failed to parse policy file: %w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return Config{}, false, fmt.Errorf("unknown policy keys: %v", undecoded)
	}
	cfg.DefaultProfile = strings.TrimSpace(strings.ToLower(cfg.DefaultProfile))
	return cfg, true, nil
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
	cleaned := filepath.Clean(path)
	parts := strings.Split(cleaned, string(os.PathSeparator))

	cur := ""
	if filepath.IsAbs(cleaned) {
		cur = string(os.PathSeparator)
	}
	if vol := filepath.VolumeName(cleaned); vol != "" {
		cur = vol
	}
	for _, part := range parts {
		if part == "" || part == "." || part == string(os.PathSeparator) {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("failed to validate policy path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("policy path must not contain symlink component: %s", cur)
		}
	}
	return nil
}
