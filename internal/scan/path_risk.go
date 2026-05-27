package scan

import (
	"path/filepath"
	"strings"
	"unicode"

	"github.com/watany-dev/gokui/internal/rule"
	"golang.org/x/text/unicode/norm"
)

func classifyPathRisks(relPath string) []Finding {
	components := pathRiskComponents(relPath)
	rawComponents := pathRiskRawComponents(relPath)
	findings := make([]Finding, 0, 2)
	hasMixedScript := false
	hasConfusable := false
	for i, component := range components {
		rawComponent := ""
		if i < len(rawComponents) {
			rawComponent = rawComponents[i]
		}
		if !hasMixedScript && hasMixedScriptLetters(component) {
			hasMixedScript = true
		}
		if !hasConfusable && (hasASCIIConfusableFilename(component) || hasConfusableExtension(rawComponent) || isNFKCASCIILetterToken(component) || isNFKCNonASCIIFilenameLikeToken(rawComponent)) {
			hasConfusable = true
		}
		if hasMixedScript && hasConfusable {
			break
		}
	}
	if hasMixedScript {
		findings = append(findings, newFinding(
			rule.MixedScriptFilename,
			filepath.ToSlash(relPath),
			1,
			"path contains mixed writing scripts in filename or directory name",
		))
	}
	if hasConfusable {
		findings = append(findings, newFinding(
			rule.ConfusableFilename,
			filepath.ToSlash(relPath),
			1,
			"path mixes ASCII with confusable non-ASCII characters in filename or directory name",
		))
	}
	return findings
}

func pathRiskComponents(relPath string) []string {
	rawParts := pathRiskRawComponents(relPath)
	components := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		stem := strings.TrimSuffix(part, filepath.Ext(part))
		if stem == "" {
			stem = part
		}
		components = append(components, stem)
	}
	return components
}

func pathRiskRawComponents(relPath string) []string {
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	components := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			continue
		}
		components = append(components, part)
	}
	return components
}

func hasMixedScriptLetters(name string) bool {
	scripts := make(map[string]struct{}, 2)
	for _, r := range name {
		if !unicode.IsLetter(r) {
			continue
		}
		if script, ok := runeScriptGroup(r); ok {
			scripts[script] = struct{}{}
			if len(scripts) > 1 {
				return true
			}
		}
	}
	return false
}

func hasConfusableExtension(name string) bool {
	ext := strings.TrimPrefix(filepath.Ext(name), ".")
	if ext == "" && strings.HasPrefix(name, ".") && len(name) > 1 && !strings.Contains(name[1:], ".") {
		// Dotfile-like tokens such as ".ｍｄ" are treated as extension-shaped
		// names for confusable checks.
		ext = name[1:]
	}
	if ext == "" {
		return false
	}
	if hasASCIIConfusableFilename(ext) {
		return true
	}
	// Also treat all-compatibility extension tokens (for example fullwidth
	// ".ｍｄ") as confusable even when the original token contains no ASCII.
	return isNFKCASCIILetterToken(ext)
}

func hasASCIIConfusableFilename(name string) bool {
	hasASCIIAlnum := false
	hasNonASCIIConfusable := false
	for _, r := range name {
		if r <= unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			hasASCIIAlnum = true
			continue
		}
		if _, ok := confusableFilenameRunes[r]; ok || isFullwidthASCIIConfusable(r) || isNFKCASCIIAlnumConfusable(r) || isDotLikeConfusable(r) {
			hasNonASCIIConfusable = true
		}
	}
	return hasASCIIAlnum && hasNonASCIIConfusable
}

func isNFKCASCIIAlnumToken(value string) bool {
	if value == "" {
		return false
	}
	normalized := norm.NFKC.String(value)
	if normalized == "" || normalized == value {
		return false
	}
	for _, r := range normalized {
		if r > unicode.MaxASCII {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func isNFKCASCIILetterToken(value string) bool {
	if !isNFKCASCIIAlnumToken(value) {
		return false
	}
	normalized := norm.NFKC.String(value)
	for _, r := range normalized {
		if r <= unicode.MaxASCII && unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func isNFKCNonASCIIFilenameLikeToken(value string) bool {
	if value == "" || containsASCII(value) {
		return false
	}
	normalized := norm.NFKC.String(value)
	if normalized == "" || normalized == value {
		return false
	}
	hasLetter := false
	for _, r := range normalized {
		if r > unicode.MaxASCII {
			return false
		}
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
		case r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return hasLetter
}

func containsASCII(value string) bool {
	for _, r := range value {
		if r <= unicode.MaxASCII {
			return true
		}
	}
	return false
}

func isFullwidthASCIIConfusable(r rune) bool {
	switch {
	case r >= '０' && r <= '９':
		return true
	case r >= 'Ａ' && r <= 'Ｚ':
		return true
	case r >= 'ａ' && r <= 'ｚ':
		return true
	default:
		return false
	}
}

func isDotLikeConfusable(r rune) bool {
	switch r {
	case '．', '｡', '。', '﹒', '․':
		return true
	default:
		return false
	}
}

func isNFKCASCIIAlnumConfusable(r rune) bool {
	if r <= unicode.MaxASCII {
		return false
	}
	normalized := norm.NFKC.String(string(r))
	if normalized == "" || normalized == string(r) {
		return false
	}
	for _, nr := range normalized {
		if nr > unicode.MaxASCII {
			return false
		}
		if !unicode.IsLetter(nr) && !unicode.IsDigit(nr) {
			return false
		}
	}
	return true
}

func runeScriptGroup(r rune) (string, bool) {
	switch {
	case unicode.In(r, unicode.Latin):
		return "Latin", true
	case unicode.In(r, unicode.Cyrillic):
		return "Cyrillic", true
	case unicode.In(r, unicode.Greek):
		return "Greek", true
	case unicode.In(r, unicode.Han):
		return "Han", true
	case unicode.In(r, unicode.Hiragana):
		return "Hiragana", true
	case unicode.In(r, unicode.Katakana):
		return "Katakana", true
	case unicode.In(r, unicode.Hangul):
		return "Hangul", true
	case unicode.In(r, unicode.Arabic):
		return "Arabic", true
	case unicode.In(r, unicode.Hebrew):
		return "Hebrew", true
	case unicode.In(r, unicode.Devanagari):
		return "Devanagari", true
	default:
		return "", false
	}
}
