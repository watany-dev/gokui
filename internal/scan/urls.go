package scan

import (
	"net"
	neturl "net/url"
	"strconv"
	"strings"

	"github.com/watany-dev/gokui/internal/rule"
	"golang.org/x/net/idna"
)

func classifyURLRisks(line string, relPath string, lineNum int, isMarkdown bool) []Finding {
	matches := extractURLCandidates(line)
	if len(matches) == 0 {
		return nil
	}

	out := make([]Finding, 0, len(matches))
	for _, raw := range matches {
		parsed, err := neturl.Parse(raw)
		if err != nil {
			continue
		}
		host := normalizeURLRiskHost(parsed.Hostname())
		if host == "" {
			continue
		}

		if ip := parseRawIPHost(host); ip != nil {
			out = append(out, newFinding(rule.RawIPURL, relPath, lineNum, "URL points to a raw IP host"))
		}
		if matchesDomainSet(host, urlShortenerHosts) {
			out = append(out, newFinding(rule.URLShortener, relPath, lineNum, "URL shortener host detected"))
		}
		if matchesDomainSet(host, pasteSiteHosts) {
			out = append(out, newFinding(rule.PasteSiteURL, relPath, lineNum, "paste site URL detected"))
		}
		if isGitHubReleaseAssetURL(host, parsed.Path) {
			out = append(out, newFinding(rule.ReleaseAssetURL, relPath, lineNum, "release asset URL detected"))
		}
		if isMarkdown && isRemoteImageLine(line) && isImagePath(parsed.Path) {
			out = append(out, newFinding(rule.RemoteImageURL, relPath, lineNum, "remote image URL detected in markdown content"))
		}
	}
	return out
}

func isGitHubReleaseAssetURL(host string, path string) bool {
	lowerPath := strings.ToLower(path)
	if host == "github.com" && (strings.Contains(lowerPath, "/releases/download/") || strings.Contains(lowerPath, "/releases/latest/download/")) {
		return true
	}
	if host == "api.github.com" {
		if isGitHubAPIReleaseAssetIDPath(lowerPath) || isGitHubAPIReleaseIDAssetsPath(lowerPath) {
			return true
		}
	}
	if host == "uploads.github.com" {
		if isGitHubAPIReleaseIDAssetsPath(lowerPath) {
			return true
		}
	}
	if host == "github-releases.githubusercontent.com" {
		return true
	}
	if host == "objects.githubusercontent.com" && strings.Contains(lowerPath, "github-production-release-asset-") {
		return true
	}
	return false
}

func isGitHubAPIReleaseAssetIDPath(path string) bool {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return false
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) != 6 {
		return false
	}
	if parts[0] != "repos" || parts[1] == "" || parts[2] == "" || parts[3] != "releases" || parts[4] != "assets" {
		return false
	}
	for _, ch := range parts[5] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return parts[5] != ""
}

func isGitHubAPIReleaseIDAssetsPath(path string) bool {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return false
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) != 6 {
		return false
	}
	if parts[0] != "repos" || parts[1] == "" || parts[2] == "" || parts[3] != "releases" || parts[5] != "assets" {
		return false
	}
	for _, ch := range parts[4] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return parts[4] != ""
}

func normalizeURLRiskHost(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(host))
	normalized = strings.TrimPrefix(normalized, "www.")
	normalized = strings.TrimSuffix(normalized, ".")
	if ascii, err := idna.Lookup.ToASCII(normalized); err == nil && ascii != "" {
		normalized = strings.ToLower(ascii)
	}
	normalized = strings.TrimPrefix(normalized, "www.")
	normalized = strings.TrimSuffix(normalized, ".")
	return normalized
}

func matchesDomainSet(host string, domains map[string]struct{}) bool {
	if host == "" {
		return false
	}
	if _, ok := domains[host]; ok {
		return true
	}
	for domain := range domains {
		if strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func parseRawIPHost(host string) net.IP {
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	if dottedIPv4, ok := parseDottedMixedBaseIPv4Host(host); ok {
		return dottedIPv4
	}
	if abbreviatedIPv4, ok := parseAbbreviatedDottedIPv4Host(host); ok {
		return abbreviatedIPv4
	}
	if numericIPv4, ok := parseIntegerIPv4Host(host); ok {
		return numericIPv4
	}
	// IPv6 zone identifiers (for example "fe80::1%eth0") are valid URL hosts
	// but net.ParseIP does not accept them directly.
	if strings.Contains(host, ":") {
		if zoneIndex := strings.Index(host, "%"); zoneIndex > 0 {
			return net.ParseIP(host[:zoneIndex])
		}
	}
	return nil
}

func parseIntegerIPv4Host(host string) (net.IP, bool) {
	if host == "" {
		return nil, false
	}

	base := 10
	number := host
	if len(host) > 2 && (strings.HasPrefix(host, "0x") || strings.HasPrefix(host, "0X")) {
		base = 16
		number = host[2:]
		if number == "" {
			return nil, false
		}
		for i := 0; i < len(number); i++ {
			c := number[i]
			isDigit := c >= '0' && c <= '9'
			isLowerHex := c >= 'a' && c <= 'f'
			isUpperHex := c >= 'A' && c <= 'F'
			if !isDigit && !isLowerHex && !isUpperHex {
				return nil, false
			}
		}
	} else if len(host) > 1 && host[0] == '0' {
		base = 8
		for i := 1; i < len(host); i++ {
			if host[i] < '0' || host[i] > '7' {
				return nil, false
			}
		}
	} else {
		for i := 0; i < len(host); i++ {
			if host[i] < '0' || host[i] > '9' {
				return nil, false
			}
		}
	}
	value, err := strconv.ParseUint(number, base, 32)
	if err != nil {
		return nil, false
	}
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)), true
}

func parseDottedMixedBaseIPv4Host(host string) (net.IP, bool) {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return nil, false
	}
	values := [4]byte{}
	for i, part := range parts {
		parsed, ok := parseIPv4OctetWithMixedBase(part)
		if !ok {
			return nil, false
		}
		values[i] = byte(parsed)
	}
	return net.IPv4(values[0], values[1], values[2], values[3]), true
}

func parseAbbreviatedDottedIPv4Host(host string) (net.IP, bool) {
	parts := strings.Split(host, ".")
	if len(parts) != 2 && len(parts) != 3 {
		return nil, false
	}
	if len(parts) == 2 {
		a, ok := parseIPv4OctetWithMixedBase(parts[0])
		if !ok {
			return nil, false
		}
		b, ok := parseIPv4IntegerComponent(parts[1], 24)
		if !ok {
			return nil, false
		}
		return net.IPv4(byte(a), byte(b>>16), byte(b>>8), byte(b)), true
	}
	a, ok := parseIPv4OctetWithMixedBase(parts[0])
	if !ok {
		return nil, false
	}
	b, ok := parseIPv4OctetWithMixedBase(parts[1])
	if !ok {
		return nil, false
	}
	c, ok := parseIPv4IntegerComponent(parts[2], 16)
	if !ok {
		return nil, false
	}
	return net.IPv4(byte(a), byte(b), byte(c>>8), byte(c)), true
}

func parseIPv4OctetWithMixedBase(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	base := 10
	number := value
	if len(value) > 2 && (strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X")) {
		base = 16
		number = value[2:]
		if number == "" {
			return 0, false
		}
		for i := 0; i < len(number); i++ {
			c := number[i]
			isDigit := c >= '0' && c <= '9'
			isLowerHex := c >= 'a' && c <= 'f'
			isUpperHex := c >= 'A' && c <= 'F'
			if !isDigit && !isLowerHex && !isUpperHex {
				return 0, false
			}
		}
	} else if len(value) > 1 && value[0] == '0' {
		base = 8
		for i := 1; i < len(value); i++ {
			if value[i] < '0' || value[i] > '7' {
				return 0, false
			}
		}
	} else {
		for i := 0; i < len(value); i++ {
			if value[i] < '0' || value[i] > '9' {
				return 0, false
			}
		}
	}
	parsed, err := strconv.ParseUint(number, base, 16)
	if err != nil || parsed > 255 {
		return 0, false
	}
	return parsed, true
}

func parseIPv4IntegerComponent(value string, bits int) (uint64, bool) {
	if value == "" || bits <= 0 || bits > 32 {
		return 0, false
	}
	base := 10
	number := value
	if len(value) > 2 && (strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X")) {
		base = 16
		number = value[2:]
		if number == "" {
			return 0, false
		}
		for i := 0; i < len(number); i++ {
			c := number[i]
			isDigit := c >= '0' && c <= '9'
			isLowerHex := c >= 'a' && c <= 'f'
			isUpperHex := c >= 'A' && c <= 'F'
			if !isDigit && !isLowerHex && !isUpperHex {
				return 0, false
			}
		}
	} else if len(value) > 1 && value[0] == '0' {
		base = 8
		for i := 1; i < len(value); i++ {
			if value[i] < '0' || value[i] > '7' {
				return 0, false
			}
		}
	} else {
		for i := 0; i < len(value); i++ {
			if value[i] < '0' || value[i] > '9' {
				return 0, false
			}
		}
	}
	parsed, err := strconv.ParseUint(number, base, bits)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func extractURLCandidates(line string) []string {
	base := urlPattern.FindAllString(line, -1)
	ipv6 := ipv6URLPattern.FindAllString(line, -1)
	if len(base) == 0 && len(ipv6) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(base)+len(ipv6))
	out := make([]string, 0, len(base)+len(ipv6))
	for _, raw := range base {
		if isBracketedIPv6PrefixFragment(raw, ipv6) {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	for _, raw := range ipv6 {
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out
}

func isBracketedIPv6PrefixFragment(candidate string, ipv6Matches []string) bool {
	if !strings.Contains(candidate, "[") || strings.Contains(candidate, "]") {
		return false
	}
	for _, full := range ipv6Matches {
		if strings.HasPrefix(full, candidate) {
			return true
		}
	}
	return false
}

func isRemoteImageLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(line, "![") || strings.Contains(lower, "<img")
}

func isImagePath(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".png") ||
		strings.HasSuffix(lower, ".jpg") ||
		strings.HasSuffix(lower, ".jpeg") ||
		strings.HasSuffix(lower, ".gif") ||
		strings.HasSuffix(lower, ".webp") ||
		strings.HasSuffix(lower, ".svg") ||
		strings.HasSuffix(lower, ".bmp") ||
		strings.HasSuffix(lower, ".ico")
}
