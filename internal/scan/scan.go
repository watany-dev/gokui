package scan

import (
	"fmt"
	"net"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maxScanFileBytes = 500_000

// Finding represents one scan result.
type Finding struct {
	ID       string
	Severity string
	File     string
	Line     int
	Summary  string
}

var (
	curlPipePattern = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sh|bash|zsh|pwsh|powershell)\b`)
	base64PipeExec  = regexp.MustCompile(`(?i)\b(?:base64|openssl\s+base64)\b[^\n|]{0,300}\|\s*(?:sh|bash|zsh|pwsh|powershell|python|node)\b`)

	promptOverridePattern = regexp.MustCompile(`(?i)\b(?:ignore|override|bypass)\b.{0,80}\b(?:previous|prior|system|higher|earlier)\b.{0,40}\b(?:instruction|instructions|prompt|prompts)\b`)

	externalBinaryPattern = regexp.MustCompile(`(?i)\bhttps?://\S+\.(?:zip|exe|msi|dmg|pkg|tar\.gz|tgz)\b`)
	urlPattern            = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"')\]]+`)
	rawHTMLPattern        = regexp.MustCompile(`(?i)<\s*(?:script|iframe|object|embed|form|link|meta|img|svg|video|audio)\b`)
	markdownLinkPattern   = regexp.MustCompile(`\[(?P<label>[^\]]+)\]\((?P<target>https?://[^)\s]+)\)`)

	fakePrereqPattern = regexp.MustCompile(`(?i)\b(?:required|required prerequisite|you must|before use)\b.{0,120}\b(?:download|install)\b.{0,200}\b(?:run|execute|bash|sh|powershell|chmod \+x)\b`)
)

type scanTarget struct {
	Absolute string
	Relative string
	Kind     string
}

var scriptLikeExtensions = map[string]struct{}{
	".sh":   {},
	".bash": {},
	".zsh":  {},
	".ps1":  {},
	".bat":  {},
	".cmd":  {},
	".py":   {},
	".js":   {},
	".ts":   {},
	".mjs":  {},
	".cjs":  {},
	".rb":   {},
	".go":   {},
}

var urlShortenerHosts = map[string]struct{}{
	"bit.ly":      {},
	"tinyurl.com": {},
	"t.co":        {},
	"goo.gl":      {},
	"ow.ly":       {},
	"is.gd":       {},
	"buff.ly":     {},
	"cutt.ly":     {},
	"rb.gy":       {},
	"shorturl.at": {},
}

var pasteSiteHosts = map[string]struct{}{
	"pastebin.com":               {},
	"hastebin.com":               {},
	"ghostbin.com":               {},
	"dpaste.com":                 {},
	"gist.github.com":            {},
	"gist.githubusercontent.com": {},
}

// ScanSkillRoot scans markdown instruction files under skillRoot.
func ScanSkillRoot(skillRoot string) ([]Finding, error) {
	targets, err := scanTargets(skillRoot)
	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0)
	for _, target := range targets {
		fileFindings, err := scanTextFile(target)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fileFindings...)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity < findings[j].Severity
		}
		return findings[i].ID < findings[j].ID
	})

	return findings, nil
}

func scanTargets(skillRoot string) ([]scanTarget, error) {
	entries := make([]scanTarget, 0, 16)
	err := filepath.WalkDir(skillRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(skillRoot, path)
		if err != nil {
			return fmt.Errorf("failed to compute relative path for scan: %w", err)
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		lower := strings.ToLower(d.Name())
		if strings.HasSuffix(lower, ".md") {
			entries = append(entries, scanTarget{
				Absolute: path,
				Relative: rel,
				Kind:     "markdown",
			})
			return nil
		}
		ext := strings.ToLower(filepath.Ext(lower))
		if _, ok := scriptLikeExtensions[ext]; ok {
			entries = append(entries, scanTarget{
				Absolute: path,
				Relative: rel,
				Kind:     "script",
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed walking skill files for scan: %w", err)
	}
	return entries, nil
}

func scanTextFile(target scanTarget) ([]Finding, error) {
	info, err := os.Stat(target.Absolute)
	if err != nil {
		return nil, fmt.Errorf("failed to stat scan file %s: %w", target.Relative, err)
	}
	if info.Size() > maxScanFileBytes {
		return []Finding{{
			ID:       "LARGE_TEXT_FILE",
			Severity: "medium",
			File:     target.Relative,
			Line:     1,
			Summary:  "text file exceeds scan size limit",
		}}, nil
	}

	content, err := os.ReadFile(target.Absolute)
	if err != nil {
		return nil, fmt.Errorf("failed to read scan file %s: %w", target.Relative, err)
	}

	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	findings := make([]Finding, 0)
	for i, line := range lines {
		lineNum := i + 1
		if strings.TrimSpace(line) == "" {
			continue
		}

		if curlPipePattern.MatchString(line) {
			findings = append(findings, Finding{
				ID:       "CURL_PIPE_SHELL",
				Severity: "critical",
				File:     target.Relative,
				Line:     lineNum,
				Summary:  "network output piped directly to shell interpreter",
			})
		}
		if base64PipeExec.MatchString(line) {
			findings = append(findings, Finding{
				ID:       "BASE64_PIPE_EXEC",
				Severity: "critical",
				File:     target.Relative,
				Line:     lineNum,
				Summary:  "decoded payload piped directly to an interpreter",
			})
		}
		if isUnpinnedRuntimeToolLine(line) {
			findings = append(findings, Finding{
				ID:       "UNPINNED_RUNTIME_TOOL",
				Severity: "high",
				File:     target.Relative,
				Line:     lineNum,
				Summary:  "unpinned runtime tool execution detected",
			})
		}
		findings = append(findings, classifyURLRisks(line, target.Relative, lineNum, target.Kind == "markdown")...)
		findings = append(findings, classifyUnicodeThreats(line, target.Relative, lineNum)...)

		if target.Kind != "markdown" {
			continue
		}

		if fakePrereqPattern.MatchString(line) {
			findings = append(findings, Finding{
				ID:       "FAKE_PREREQ_EXECUTION",
				Severity: "critical",
				File:     target.Relative,
				Line:     lineNum,
				Summary:  "prerequisite text asks to download and run code",
			})
		}
		if externalBinaryPattern.MatchString(line) {
			findings = append(findings, Finding{
				ID:       "EXTERNAL_BINARY_DOWNLOAD",
				Severity: "high",
				File:     target.Relative,
				Line:     lineNum,
				Summary:  "external binary archive download instruction detected",
			})
		}
		if promptOverridePattern.MatchString(line) {
			findings = append(findings, Finding{
				ID:       "PROMPT_OVERRIDE_LANGUAGE",
				Severity: "high",
				File:     target.Relative,
				Line:     lineNum,
				Summary:  "prompt override language detected",
			})
		}
		if rawHTMLPattern.MatchString(line) {
			findings = append(findings, Finding{
				ID:       "RAW_HTML_MARKUP",
				Severity: "medium",
				File:     target.Relative,
				Line:     lineNum,
				Summary:  "raw HTML markup detected in markdown content",
			})
		}
		findings = append(findings, classifyMarkdownLinkSpoofing(line, target.Relative, lineNum)...)
	}

	return deduplicateFindings(findings), nil
}

func isUnpinnedRuntimeToolLine(line string) bool {
	fields := strings.Fields(strings.ToLower(line))
	if len(fields) == 0 {
		return false
	}

	for i := 0; i < len(fields); i++ {
		token := fields[i]
		switch token {
		case "npx", "uvx":
			j := i + 1
			for j < len(fields) && strings.HasPrefix(fields[j], "-") {
				j++
			}
			if j >= len(fields) {
				continue
			}
			if isUnpinnedPackageRef(fields[j]) {
				return true
			}
		case "go":
			if i+2 >= len(fields) || fields[i+1] != "run" {
				continue
			}
			for j := i + 2; j < len(fields); j++ {
				part := fields[j]
				if strings.HasPrefix(part, "-") {
					continue
				}
				return strings.HasSuffix(part, "@latest")
			}
		}
	}

	return false
}

func isUnpinnedPackageRef(ref string) bool {
	if ref == "" {
		return false
	}

	if strings.HasPrefix(ref, "@") {
		lastAt := strings.LastIndex(ref, "@")
		return lastAt <= 0 || lastAt == len(ref)-1 || ref[lastAt+1:] == "latest"
	}

	parts := strings.SplitN(ref, "@", 2)
	if len(parts) == 1 {
		return true
	}
	return parts[1] == "" || parts[1] == "latest"
}

func classifyURLRisks(line string, relPath string, lineNum int, isMarkdown bool) []Finding {
	matches := urlPattern.FindAllString(line, -1)
	if len(matches) == 0 {
		return nil
	}

	out := make([]Finding, 0, len(matches))
	for _, raw := range matches {
		parsed, err := neturl.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if host == "" {
			continue
		}

		if ip := net.ParseIP(host); ip != nil {
			out = append(out, Finding{
				ID:       "RAW_IP_URL",
				Severity: "high",
				File:     relPath,
				Line:     lineNum,
				Summary:  "URL points to a raw IP host",
			})
		}
		if _, ok := urlShortenerHosts[host]; ok {
			out = append(out, Finding{
				ID:       "URL_SHORTENER",
				Severity: "medium",
				File:     relPath,
				Line:     lineNum,
				Summary:  "URL shortener host detected",
			})
		}
		if _, ok := pasteSiteHosts[host]; ok {
			out = append(out, Finding{
				ID:       "PASTE_SITE_URL",
				Severity: "medium",
				File:     relPath,
				Line:     lineNum,
				Summary:  "paste site URL detected",
			})
		}
		if host == "github.com" && strings.Contains(strings.ToLower(parsed.Path), "/releases/download/") {
			out = append(out, Finding{
				ID:       "RELEASE_ASSET_URL",
				Severity: "medium",
				File:     relPath,
				Line:     lineNum,
				Summary:  "release asset URL detected",
			})
		}
		if isMarkdown && isRemoteImageLine(line) && isImagePath(parsed.Path) {
			out = append(out, Finding{
				ID:       "REMOTE_IMAGE_URL",
				Severity: "medium",
				File:     relPath,
				Line:     lineNum,
				Summary:  "remote image URL detected in markdown content",
			})
		}
	}
	return out
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

func classifyUnicodeThreats(line string, relPath string, lineNum int) []Finding {
	out := make([]Finding, 0, 2)
	hasUnicodeTag := false
	hasBidi := false

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
		if hasUnicodeTag && hasBidi {
			break
		}
	}

	return out
}

func isBidiControlRune(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

func classifyMarkdownLinkSpoofing(line string, relPath string, lineNum int) []Finding {
	matches := markdownLinkPattern.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return nil
	}

	out := make([]Finding, 0, len(matches))
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		displayHost, ok := parseDisplayLinkHost(match[1])
		if !ok {
			continue
		}
		targetHost, ok := parseURLHost(match[2])
		if !ok {
			continue
		}
		if normalizeHost(displayHost) == normalizeHost(targetHost) {
			continue
		}
		out = append(out, Finding{
			ID:       "LINK_SPOOFING_URL_MISMATCH",
			Severity: "high",
			File:     relPath,
			Line:     lineNum,
			Summary:  "markdown link label host differs from link target host",
		})
	}
	return out
}

func parseDisplayLinkHost(label string) (string, bool) {
	trimmed := strings.TrimSpace(label)
	if trimmed == "" || strings.Contains(trimmed, " ") {
		return "", false
	}
	if strings.Contains(trimmed, "://") {
		return parseURLHost(trimmed)
	}
	if !strings.Contains(trimmed, ".") {
		return "", false
	}
	return parseURLHost("https://" + trimmed)
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
	normalized = strings.TrimPrefix(normalized, "www.")
	return normalized
}

func deduplicateFindings(in []Finding) []Finding {
	seen := make(map[string]struct{}, len(in))
	out := make([]Finding, 0, len(in))
	for _, finding := range in {
		key := fmt.Sprintf("%s|%s|%d|%s", finding.ID, finding.File, finding.Line, finding.Severity)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, finding)
	}
	return out
}

// IsRejectable returns true when finding severity should reject under strict mode.
func IsRejectable(f Finding) bool {
	return f.Severity == "critical" || f.Severity == "high"
}
