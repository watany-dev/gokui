package app

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/safefs"
)

func isCanonicalSHA256Hex(in string) bool {
	if strings.TrimSpace(in) != in {
		return false
	}
	if strings.ToLower(in) != in {
		return false
	}
	decoded, err := hex.DecodeString(in)
	return err == nil && len(decoded) == 32
}

func isValidLockRelativePath(in string) bool {
	trimmed := strings.TrimSpace(in)
	if !utf8.ValidString(in) {
		return false
	}
	if strings.IndexFunc(in, isC0OrC1ControlRune) >= 0 {
		return false
	}
	if containsSeverityOverrideDisallowedUnicode(in) {
		return false
	}
	if trimmed == "" {
		return false
	}
	if trimmed != in {
		return false
	}
	if strings.Contains(in, "\\") {
		return false
	}
	cleaned := filepath.ToSlash(filepath.Clean(in))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return false
	}
	if strings.HasPrefix(cleaned, "/") {
		return false
	}
	if safefs.HasWindowsDrivePathPrefix(cleaned) {
		return false
	}
	return cleaned == in
}

func isC0OrC1ControlRune(r rune) bool {
	return (r >= 0x00 && r <= 0x1f) || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

func containsSeverityOverrideDisallowedUnicode(s string) bool {
	for _, r := range s {
		switch {
		case r >= 0x202a && r <= 0x202e:
			return true
		case r >= 0x2066 && r <= 0x2069:
			return true
		case r >= 0x200b && r <= 0x200f:
			return true
		case r >= 0xfe00 && r <= 0xfe0f:
			return true
		case r >= 0xe0100 && r <= 0xe01ef:
			return true
		case r >= 0xe0000 && r <= 0xe007f:
			return true
		case unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			return true
		}
	}
	return false
}

func validateLockFindingSummary(summary lockFindingSummary) error {
	if summary.Critical < 0 {
		return fmt.Errorf("critical count must be >= 0")
	}
	if summary.High < 0 {
		return fmt.Errorf("high count must be >= 0")
	}
	if summary.Medium < 0 {
		return fmt.Errorf("medium count must be >= 0")
	}
	if summary.Low < 0 {
		return fmt.Errorf("low count must be >= 0")
	}
	return nil
}
