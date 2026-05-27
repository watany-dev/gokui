package scan

import "strings"

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
		out = append(out, Finding{
			ID:       "ANSI_OSC_ESCAPE_IN_TEXT",
			Severity: "critical",
			File:     relPath,
			Line:     lineNum,
			Summary:  "ANSI/OSC escape sequence detected in text",
		})
	}

	for _, r := range line {
		if !hasUnicodeTag && r >= 0xE0000 && r <= 0xE007F {
			hasUnicodeTag = true
			out = append(out, Finding{
				ID:       "UNICODE_TAG_IN_INSTRUCTIONS",
				Severity: "critical",
				File:     relPath,
				Line:     lineNum,
				Summary:  "Unicode Tags detected in text",
			})
		}
		if !hasBidi && isBidiControlRune(r) {
			hasBidi = true
			out = append(out, Finding{
				ID:       "BIDI_CONTROL_IN_TEXT",
				Severity: "critical",
				File:     relPath,
				Line:     lineNum,
				Summary:  "bidi control character detected in text",
			})
		}
		if !hasVariationSelector && isVariationSelectorRune(r) {
			hasVariationSelector = true
			out = append(out, Finding{
				ID:       "VARIATION_SELECTOR_IN_TEXT",
				Severity: "critical",
				File:     relPath,
				Line:     lineNum,
				Summary:  "variation selector detected in text",
			})
		}
		if !hasZeroWidth && isZeroWidthRune(r) {
			hasZeroWidth = true
			out = append(out, Finding{
				ID:       "ZERO_WIDTH_CHAR_IN_TEXT",
				Severity: "critical",
				File:     relPath,
				Line:     lineNum,
				Summary:  "zero-width character detected in text",
			})
		}
		if !hasControl && isDisallowedControlRune(r) {
			hasControl = true
			out = append(out, Finding{
				ID:       "CONTROL_CHAR_IN_TEXT",
				Severity: "critical",
				File:     relPath,
				Line:     lineNum,
				Summary:  "disallowed control character detected in text",
			})
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
