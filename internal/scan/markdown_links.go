package scan

import (
	neturl "net/url"
	"strings"

	"github.com/watany-dev/gokui/internal/rule"
	"golang.org/x/net/idna"
)

const markdownLinkSpoofingSummary = "markdown link label host differs from link target host"

func classifyMarkdownLinkSpoofing(line string, relPath string, lineNum int) []Finding {
	matches := markdownLinkPattern.FindAllStringSubmatchIndex(line, -1)
	if len(matches) == 0 {
		return nil
	}

	out := make([]Finding, 0, len(matches))
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}
		start := match[0]
		if isUnescapedImagePrefix(line, start) {
			continue
		}
		label := line[match[2]:match[3]]
		target := line[match[4]:match[5]]
		displayHost, ok := parseDisplayLinkHost(label)
		if !ok {
			continue
		}
		targetHost, ok := parseMarkdownLinkTargetHost(target)
		if !ok {
			continue
		}
		if normalizeHost(displayHost) == normalizeHost(targetHost) {
			continue
		}
		out = append(out, newFinding(rule.LinkSpoofingURLMismatch, relPath, lineNum, markdownLinkSpoofingSummary))
	}
	return out
}

func buildMarkdownReferenceHostIndex(lines []string) map[string]string {
	hosts := make(map[string]string)
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		match := markdownReferenceDefinitionPattern.FindStringSubmatch(line)
		if len(match) < 3 {
			continue
		}
		refID := normalizeMarkdownReferenceID(match[1])
		if refID == "" {
			continue
		}
		// CommonMark resolves duplicate reference definitions using the first
		// definition in document order.
		if _, exists := hosts[refID]; exists {
			continue
		}
		target := strings.TrimSpace(match[2])
		targetHost, ok := parseMarkdownLinkTargetHost(target)
		if !ok && target == "" && i+1 < len(lines) {
			if nextHost, nextOK := parseMarkdownLinkTargetHost(lines[i+1]); nextOK {
				targetHost = nextHost
				ok = true
				i++
			}
		}
		if !ok {
			continue
		}
		hosts[refID] = targetHost
	}
	return hosts
}

func classifyMarkdownReferenceLinkSpoofing(line string, relPath string, lineNum int, referenceHosts map[string]string) []Finding {
	if len(referenceHosts) == 0 {
		return nil
	}

	matches := markdownReferenceLinkPattern.FindAllStringSubmatchIndex(line, -1)
	out := make([]Finding, 0, len(matches)+1)
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}
		start := match[0]
		if isUnescapedImagePrefix(line, start) {
			continue
		}
		label := line[match[2]:match[3]]
		refIDToken := line[match[4]:match[5]]
		if strings.TrimSpace(refIDToken) == "" {
			refIDToken = label
		}
		refID := normalizeMarkdownReferenceID(refIDToken)
		targetHost, ok := referenceHosts[refID]
		if !ok {
			continue
		}
		displayHost, ok := parseDisplayLinkHost(label)
		if !ok {
			continue
		}
		if normalizeHost(displayHost) == normalizeHost(targetHost) {
			continue
		}
		out = append(out, newFinding(rule.LinkSpoofingURLMismatch, relPath, lineNum, markdownLinkSpoofingSummary))
	}
	shortcutMatches := markdownShortcutReferencePattern.FindAllStringSubmatchIndex(line, -1)
	for _, match := range shortcutMatches {
		if len(match) < 4 {
			continue
		}
		start := match[0]
		end := match[1]
		if isUnescapedImagePrefix(line, start) {
			continue
		}
		if next := nextNonWhitespaceIndex(line, end); next >= 0 {
			switch line[next] {
			case '(', '[', ':':
				continue
			}
		}
		label := line[match[2]:match[3]]
		refID := normalizeMarkdownReferenceID(label)
		targetHost, ok := referenceHosts[refID]
		if !ok {
			continue
		}
		displayHost, ok := parseDisplayLinkHost(label)
		if !ok {
			continue
		}
		if normalizeHost(displayHost) == normalizeHost(targetHost) {
			continue
		}
		out = append(out, newFinding(rule.LinkSpoofingURLMismatch, relPath, lineNum, markdownLinkSpoofingSummary))
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func isUnescapedImagePrefix(line string, bracketStart int) bool {
	if bracketStart <= 0 || bracketStart > len(line) {
		return false
	}
	if line[bracketStart-1] != '!' {
		return false
	}
	backslashes := 0
	for i := bracketStart - 2; i >= 0 && line[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 0
}

func buildMarkdownReferenceUsageContinuationVariant(lines []string, idx int) (string, bool) {
	if idx < 0 || idx >= len(lines)-1 {
		return "", false
	}
	current := strings.TrimSpace(lines[idx])
	if current == "" || !strings.Contains(current, "]") {
		return "", false
	}
	next := strings.TrimSpace(lines[idx+1])
	if next == "" || !strings.HasPrefix(next, "[") {
		return "", false
	}
	if strings.Contains(next, "]:") {
		return "", false
	}
	return current + " " + next, true
}

func nextNonWhitespaceIndex(value string, start int) int {
	for i := start; i < len(value); i++ {
		if value[i] != ' ' && value[i] != '\t' {
			return i
		}
	}
	return -1
}

func normalizeMarkdownReferenceID(value string) string {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return ""
	}
	return strings.Join(strings.Fields(trimmed), " ")
}

func parseDisplayLinkHost(label string) (string, bool) {
	trimmed := unwrapDisplayLinkLabel(label)
	if trimmed == "" || strings.Contains(trimmed, " ") {
		return "", false
	}
	if strings.Contains(trimmed, "://") {
		return parseURLHost(trimmed)
	}
	if strings.HasPrefix(trimmed, "//") {
		return parseURLHost("https:" + trimmed)
	}
	if !containsIDNALabelSeparator(trimmed) {
		return "", false
	}
	return parseURLHost("https://" + trimmed)
}

func unwrapDisplayLinkLabel(label string) string {
	trimmed := strings.TrimSpace(label)
	for range 4 {
		previous := trimmed
		if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") && len(trimmed) > 2 {
			trimmed = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
		}
		trimmed = unwrapMarkdownEmphasis(trimmed)
		trimmed = unwrapMarkdownCodeSpan(trimmed)
		trimmed = strings.TrimSpace(trimmed)
		if trimmed == previous {
			break
		}
	}
	return trimmed
}

func unwrapMarkdownEmphasis(value string) string {
	if strings.HasPrefix(value, "**") && strings.HasSuffix(value, "**") && len(value) > 4 {
		return strings.TrimSpace(value[2 : len(value)-2])
	}
	if strings.HasPrefix(value, "__") && strings.HasSuffix(value, "__") && len(value) > 4 {
		return strings.TrimSpace(value[2 : len(value)-2])
	}
	if strings.HasPrefix(value, "*") && strings.HasSuffix(value, "*") && len(value) > 2 {
		if value[1] != '*' && value[len(value)-2] != '*' {
			return strings.TrimSpace(value[1 : len(value)-1])
		}
	}
	if strings.HasPrefix(value, "_") && strings.HasSuffix(value, "_") && len(value) > 2 {
		if value[1] != '_' && value[len(value)-2] != '_' {
			return strings.TrimSpace(value[1 : len(value)-1])
		}
	}
	return value
}

func parseMarkdownLinkTargetHost(target string) (string, bool) {
	urlValue, ok := extractMarkdownLinkTargetURL(target)
	if !ok {
		return "", false
	}
	if strings.HasPrefix(urlValue, "//") {
		return parseURLHost("https:" + urlValue)
	}
	lower := strings.ToLower(urlValue)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "", false
	}
	return parseURLHost(urlValue)
}

func extractMarkdownLinkTargetURL(target string) (string, bool) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "", false
	}
	if strings.HasPrefix(trimmed, "<") {
		end := strings.Index(trimmed, ">")
		if end <= 1 {
			return "", false
		}
		candidate := strings.TrimSpace(trimmed[1:end])
		if candidate == "" {
			return "", false
		}
		return candidate, true
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return "", false
	}
	return fields[0], true
}

func unwrapMarkdownCodeSpan(value string) string {
	if !strings.HasPrefix(value, "`") {
		return value
	}
	width := 0
	for width < len(value) && value[width] == '`' {
		width++
	}
	if width == 0 || len(value) <= width*2 {
		return value
	}
	fence := strings.Repeat("`", width)
	if !strings.HasSuffix(value, fence) {
		return value
	}
	return strings.TrimSpace(value[width : len(value)-width])
}

func containsIDNALabelSeparator(value string) bool {
	for _, r := range value {
		switch r {
		case '.', '。', '．', '｡':
			return true
		}
	}
	return false
}

func parseURLHost(raw string) (string, bool) {
	parsed, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", false
	}
	return host, true
}

func normalizeHost(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(host))
	normalized = strings.TrimSuffix(normalized, ".")
	normalized = strings.TrimPrefix(normalized, "www.")
	if ascii, err := idna.Lookup.ToASCII(normalized); err == nil && ascii != "" {
		normalized = strings.ToLower(ascii)
	}
	normalized = strings.TrimSuffix(normalized, ".")
	return normalized
}
