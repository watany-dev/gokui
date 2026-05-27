package scan

import (
	"strings"

	"github.com/watany-dev/gokui/internal/rule"
)

func classifyUnicodeThreats(line string, relPath string, lineNum int) []Finding {
	out := make([]Finding, 0, 6)
	hasUnicodeTag := false
	hasBidi := false
	hasZeroWidth := false
	hasControl := false
	hasVariationSelector := false
	hasANSIOSC := false

	if hasANSIOSCEscape(line) {
		hasANSIOSC = true
		out = append(out, newFinding(rule.ANSIOSCEscapeInText, relPath, lineNum, "ANSI/OSC escape sequence detected in text"))
	}

	for _, r := range line {
		if !hasUnicodeTag && r >= 0xE0000 && r <= 0xE007F {
			hasUnicodeTag = true
			out = append(out, newFinding(rule.UnicodeTagInInstructions, relPath, lineNum, "Unicode Tags detected in text"))
		}
		if !hasBidi && isBidiControlRune(r) {
			hasBidi = true
			out = append(out, newFinding(rule.BidiControlInText, relPath, lineNum, "bidi control character detected in text"))
		}
		if !hasVariationSelector && isVariationSelectorRune(r) {
			hasVariationSelector = true
			out = append(out, newFinding(rule.VariationSelectorInText, relPath, lineNum, "variation selector detected in text"))
		}
		if !hasZeroWidth && isZeroWidthRune(r) {
			hasZeroWidth = true
			out = append(out, newFinding(rule.ZeroWidthCharInText, relPath, lineNum, "zero-width character detected in text"))
		}
		if !hasControl && isDisallowedControlRune(r) {
			hasControl = true
			out = append(out, newFinding(rule.ControlCharInText, relPath, lineNum, "disallowed control character detected in text"))
		}
		if hasUnicodeTag && hasBidi && hasZeroWidth && hasControl && hasVariationSelector && hasANSIOSC {
			break
		}
	}

	return out
}

func isBidiControlRune(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

func isZeroWidthRune(r rune) bool {
	return (r >= 0x200B && r <= 0x200F) || r == 0x2060 || r == 0xFEFF
}

func isDisallowedControlRune(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return (r >= 0x00 && r <= 0x1F) || (r >= 0x7F && r <= 0x9F)
}

func isVariationSelectorRune(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF)
}

func hasANSIOSCEscape(line string) bool {
	return strings.Contains(line, "\x1b[") || strings.Contains(line, "\x1b]")
}
