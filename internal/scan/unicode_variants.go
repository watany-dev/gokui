package scan

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

func normalizeLineNFKC(line string) (string, bool) {
	if isASCII(line) {
		return line, false
	}
	normalized := norm.NFKC.String(line)
	return normalized, normalized != line
}

func lineVariants(raw string, normalized string, hasNormalized bool) []string {
	if !hasNormalized {
		return []string{raw}
	}
	return []string{raw, normalized}
}

func scanLineVariants(lines []string, idx int, raw string, normalized string, hasNormalized bool) []string {
	variants := lineVariants(raw, normalized, hasNormalized)
	joined, ok := buildContinuationVariant(lines, idx)
	if !ok {
		return variants
	}
	joinedNormalized, joinedChanged := normalizeLineNFKC(joined)
	return append(variants, lineVariants(joined, joinedNormalized, joinedChanged)...)
}

func buildContinuationVariant(lines []string, idx int) (string, bool) {
	if idx < 0 || idx >= len(lines) {
		return "", false
	}
	start := strings.TrimSpace(lines[idx])
	if !shouldJoinWithNextLine(start) {
		return "", false
	}

	parts := []string{trimContinuationSegment(start)}
	added := 0
	for j := idx + 1; j < len(lines) && added < maxJoinedContinuationLines; j++ {
		next := strings.TrimSpace(lines[j])
		if next == "" {
			break
		}
		parts = append(parts, trimContinuationSegment(next))
		added++
		joined := strings.Join(parts, " ")
		if !shouldJoinWithNextLine(joined) {
			return joined, true
		}
	}
	if len(parts) > 1 {
		return strings.Join(parts, " "), true
	}
	return "", false
}

func trimContinuationSegment(segment string) string {
	trimmed := strings.TrimSpace(segment)
	if strings.HasSuffix(trimmed, "\\") {
		return strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
	}
	return trimmed
}

func shouldJoinWithNextLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	if strings.HasSuffix(trimmed, "\\") || strings.HasSuffix(trimmed, "|") || strings.HasSuffix(trimmed, "||") || strings.HasSuffix(trimmed, "&&") {
		return true
	}
	if strings.Contains(trimmed, "$(") && !strings.Contains(trimmed, ")") {
		return true
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}
