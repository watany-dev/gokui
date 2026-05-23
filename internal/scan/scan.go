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
	"unicode"

	"golang.org/x/text/unicode/norm"
)

const maxScanFileBytes = 500_000

var scanMaxFiles = 10_000

const (
	ruleScanSymlinkInSource = "SYMLINK_IN_SCAN_SOURCE"
	ruleScanFileCount       = "SCAN_FILE_COUNT_EXCEEDED"
)

// Finding represents one scan result.
type Finding struct {
	ID       string
	Severity string
	File     string
	Line     int
	Summary  string
}

var (
	curlPipePattern               = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sh|bash|zsh|pwsh|powershell|python3?|node|ruby|perl)\b`)
	curlSubshellExecPattern       = regexp.MustCompile(`(?i)\b(?:sh|bash|zsh|pwsh|powershell|eval|python3?|node|ruby|perl)\b[^\n]{0,200}\$\(\s*(?:curl|wget)\b`)
	curlBacktickExecPattern       = regexp.MustCompile("(?i)\\b(?:sh|bash|zsh|pwsh|powershell|eval|python3?|node|ruby|perl)\\b[^\\n]{0,200}`\\s*(?:curl|wget)\\b")
	powerShellRemoteEvalPattern   = regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b[^\n]{0,260}(?:\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl(?:\.exe)?|wget(?:\.exe)?)\b[^\n]{0,220}https?://|\bdownload(?:string|data)\b\s*\(\s*['"]?https?://)`)
	powerShellFetchEvalPattern    = regexp.MustCompile(`(?i)(?:\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl(?:\.exe)?|wget(?:\.exe)?)\b[^\n]{0,260}https?://[^\n]{0,260}\b(?:iex|invoke-expression)\b|\bdownload(?:string|data)\b\s*\(\s*['"]?https?://[^\n]{0,260}\b(?:iex|invoke-expression)\b)`)
	pythonRemoteExecPattern       = regexp.MustCompile(`(?i)\b(?:exec|eval)\s*\(\s*(?:requests\.get\s*\(\s*['"]https?://[^'"]+['"]\s*\)\.text|urllib\.request\.urlopen\s*\(\s*['"]https?://[^'"]+['"]\s*\)\.read\s*\(\s*\))`)
	nodeRemoteEvalPattern         = regexp.MustCompile(`(?i)\beval\s*\(\s*(?:(?:await\s+)?fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)|(?:await\s+)?\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\)|\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\))`)
	nodeRemoteFunctionExecPattern = regexp.MustCompile(`(?i)\bnew\s+function\s*\(\s*(?:(?:await\s+)?\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\)|\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\))\s*\)\s*\(`)
	rubyRemoteEvalPattern         = regexp.MustCompile(`(?i)\beval\s*\(\s*(?:net::http\.get\s*\(\s*uri\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)|uri\.open\s*\(\s*['"]https?://[^'"]+['"]\s*\)\.read)`)
	base64PipeExec                = regexp.MustCompile(`(?i)\b(?:base64|openssl\s+base64)\b[^\n|]{0,300}\|\s*(?:sh|bash|zsh|pwsh|powershell|python|node)\b`)
	hexPipeExec                   = regexp.MustCompile(`(?i)\b(?:xxd\s+-r(?:\s+-p)?|unhexlify|fromhex|hexdecode)\b[^\n|]{0,300}\|\s*(?:sh|bash|zsh|pwsh|powershell|python|node)\b`)
	encodedCmdExec                = regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,240}\s-(?:encodedcommand|enc)\s+[a-z0-9+/=]{12,}\b`)

	promptOverridePattern = regexp.MustCompile(`(?i)\b(?:ignore|override|bypass)\b.{0,80}\b(?:previous|prior|system|higher|earlier)\b.{0,40}\b(?:instruction|instructions|prompt|prompts)\b`)

	externalBinaryPattern     = regexp.MustCompile(`(?i)\bhttps?://\S+\.(?:zip|exe|msi|dmg|pkg|tar\.gz|tgz)\b`)
	urlPattern                = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"')\]]+`)
	rawHTMLPattern            = regexp.MustCompile(`(?i)<\s*(?:script|iframe|object|embed|form|link|meta|img|svg|video|audio)\b`)
	markdownLinkPattern       = regexp.MustCompile(`\[(?P<label>[^\]]+)\]\((?P<target>https?://[^)\s]+)\)`)
	passwordArchivePattern    = regexp.MustCompile(`(?i)(?:\b(?:password|passphrase|passwd|encrypted)\b.{0,80}\b(?:zip|7z|rar|archive|tar|tgz|tar\.gz)\b|\b(?:zip|7z|rar|archive|tar|tgz|tar\.gz)\b.{0,80}\b(?:password|passphrase|passwd|encrypted)\b)`)
	goSemverExactPattern      = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:-[0-9a-z.-]+)?(?:\+[0-9a-z.-]+)?$`)
	goPseudoVersionPattern    = regexp.MustCompile(`^v\d+\.\d+\.\d+-\d{14}-[0-9a-f]{12}$`)
	hexCommitRefPattern       = regexp.MustCompile(`^[0-9a-f]{12,40}$`)
	remoteScriptImportPattern = regexp.MustCompile(`(?i)\b(?:source|bash|sh|zsh)\b\s*<\(\s*(?:curl|wget)\b`)
	remoteDenoRunPattern      = regexp.MustCompile(`(?i)\bdeno\b\s+run\b[^\n]{0,300}\bhttps?://`)

	fakePrereqPattern = regexp.MustCompile(`(?i)\b(?:required|required prerequisite|you must|before use)\b.{0,120}\b(?:download|install)\b.{0,200}\b(?:run|execute|bash|sh|powershell|chmod \+x)\b`)
)

var promptOverridePhrases = [][]string{
	{"ignore", "previous", "instructions"},
	{"ignore", "all", "previous", "instructions"},
	{"disregard", "previous", "instructions"},
	{"override", "system", "prompt"},
	{"bypass", "safety", "instructions"},
}

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

var homeConfigPathHints = []string{
	"~/.bashrc",
	"~/.zshrc",
	"~/.profile",
	"~/.bash_profile",
	"~/.config/fish/config.fish",
	"~/.ssh/config",
	"~/.ssh/authorized_keys",
	"~/library/launchagents/",
	"/etc/profile",
	"/etc/bash.bashrc",
	"/etc/zsh/zshrc",
	"/etc/cron.d/",
	"/etc/cron.daily/",
	"/etc/cron.hourly/",
	"/etc/cron.weekly/",
	"/etc/cron.monthly/",
	"/var/spool/cron/",
}

var secretPathHints = []string{
	".env",
	"~/.ssh/",
	"/.ssh/",
	"~/.aws/",
	"/.aws/",
	"id_rsa",
	"id_ed25519",
	"credentials",
	"api_key",
	"token",
	"cookies",
	"keychain",
	"wallet",
}

var secretExfilNetworkCommand = regexp.MustCompile(`(?i)\b(?:curl|wget|invoke-webrequest|invoke-restmethod|requests\.post|netcat|nc)\b`)
var bashWildcardPermissionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\ballowed(?:[_ -]?tools?)\b.*\bbash\b.*(?:\*|\ball\b)`),
	regexp.MustCompile(`(?i)\bbash\b.*(?:\*|\ball\b).*allowed(?:[_ -]?tools?)\b`),
	regexp.MustCompile(`(?i)\btool(?:[_ -]?permissions?)\b.*\bbash\b.*(?:\*|\ball\b)`),
	regexp.MustCompile(`(?i)\bbash\s*\(\s*\*\s*\)`),
}

// ScanSkillRoot scans markdown instruction files under skillRoot.
func ScanSkillRoot(skillRoot string) ([]Finding, error) {
	targets, err := scanTargets(skillRoot)
	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0)
	for _, target := range targets {
		findings = append(findings, classifyPathRisks(target.Relative)...)
		if target.Kind == "unknown" {
			findings = append(findings, Finding{
				ID:       "UNKNOWN_FILE_TYPE",
				Severity: "medium",
				File:     target.Relative,
				Line:     1,
				Summary:  "unclassified file type requires manual review",
			})
			continue
		}
		fileFindings, err := scanTextFile(target)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fileFindings...)
	}
	findings = deduplicateFindings(findings)

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

func classifyPathRisks(relPath string) []Finding {
	name := filepath.Base(relPath)
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	if stem == "" {
		stem = name
	}
	if !hasMixedScriptLetters(stem) {
		return nil
	}
	return []Finding{
		{
			ID:       "MIXED_SCRIPT_FILENAME",
			Severity: "medium",
			File:     filepath.ToSlash(relPath),
			Line:     1,
			Summary:  "filename contains mixed writing scripts",
		},
	}
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

func scanTargets(skillRoot string) ([]scanTarget, error) {
	entries := make([]scanTarget, 0, 16)
	scannedFiles := 0
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
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: scan source contains symlink: %s", ruleScanSymlinkInSource, rel)
		}
		if d.IsDir() {
			return nil
		}
		scannedFiles++
		if scannedFiles > scanMaxFiles {
			return fmt.Errorf("%s: scan source exceeded max file count: %d", ruleScanFileCount, scanMaxFiles)
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
			return nil
		}
		entries = append(entries, scanTarget{
			Absolute: path,
			Relative: rel,
			Kind:     "unknown",
		})
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

		normalized, changed := normalizeLineNFKC(line)
		if changed {
			findings = append(findings, Finding{
				ID:       "NFKC_CHANGES_TEXT",
				Severity: "medium",
				File:     target.Relative,
				Line:     lineNum,
				Summary:  "Unicode compatibility normalization changes text",
			})
		}
		for _, variant := range lineVariants(line, normalized, changed) {
			if curlPipePattern.MatchString(variant) || curlSubshellExecPattern.MatchString(variant) || curlBacktickExecPattern.MatchString(variant) || powerShellRemoteEvalPattern.MatchString(variant) || powerShellFetchEvalPattern.MatchString(variant) || pythonRemoteExecPattern.MatchString(variant) || nodeRemoteEvalPattern.MatchString(variant) || nodeRemoteFunctionExecPattern.MatchString(variant) || rubyRemoteEvalPattern.MatchString(variant) {
				findings = append(findings, Finding{
					ID:       "CURL_PIPE_SHELL",
					Severity: "critical",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "network output reaches shell/interpreter execution",
				})
			}
			if base64PipeExec.MatchString(variant) {
				findings = append(findings, Finding{
					ID:       "BASE64_PIPE_EXEC",
					Severity: "critical",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "decoded payload piped directly to an interpreter",
				})
			}
			if hexPipeExec.MatchString(variant) {
				findings = append(findings, Finding{
					ID:       "HEX_PIPE_EXEC",
					Severity: "critical",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "hex-decoded payload piped directly to an interpreter",
				})
			}
			if encodedCmdExec.MatchString(variant) {
				findings = append(findings, Finding{
					ID:       "ENCODED_COMMAND_EXEC",
					Severity: "critical",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "encoded command execution flag detected",
				})
			}
			if hasChmodExecChain(variant) {
				findings = append(findings, Finding{
					ID:       "CHMOD_EXEC_CHAIN",
					Severity: "critical",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "chmod +x followed by execution of the same local artifact",
				})
			}
			if hasHomeConfigWrite(variant) {
				findings = append(findings, Finding{
					ID:       "WRITES_HOME_CONFIG",
					Severity: "high",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "writes to shell/ssh/cron/launch-agent configuration path",
				})
			}
			if hasSecretExfilLine(variant) {
				findings = append(findings, Finding{
					ID:       "SECRET_EXFIL",
					Severity: "critical",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "secret path access combined with network exfiltration command",
				})
			}
			if hasBashWildcardPermission(variant) {
				findings = append(findings, Finding{
					ID:       "ALLOWED_TOOLS_BASH_WILDCARD",
					Severity: "high",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "broad Bash wildcard permission detected",
				})
			}
			if isUnpinnedRuntimeToolLine(variant) {
				findings = append(findings, Finding{
					ID:       "UNPINNED_RUNTIME_TOOL",
					Severity: "high",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "unpinned runtime tool execution detected",
				})
			}
			findings = append(findings, classifyURLRisks(variant, target.Relative, lineNum, target.Kind == "markdown")...)
		}
		findings = append(findings, classifyUnicodeThreats(line, target.Relative, lineNum)...)

		if target.Kind != "markdown" {
			continue
		}

		for _, variant := range lineVariants(line, normalized, changed) {
			if fakePrereqPattern.MatchString(variant) {
				findings = append(findings, Finding{
					ID:       "FAKE_PREREQ_EXECUTION",
					Severity: "critical",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "prerequisite text asks to download and run code",
				})
			}
			if externalBinaryPattern.MatchString(variant) {
				findings = append(findings, Finding{
					ID:       "EXTERNAL_BINARY_DOWNLOAD",
					Severity: "high",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "external binary archive download instruction detected",
				})
			}
			if promptOverridePattern.MatchString(variant) || hasPromptOverrideApproximatePhrase(variant) {
				findings = append(findings, Finding{
					ID:       "PROMPT_OVERRIDE_LANGUAGE",
					Severity: "high",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "prompt override language detected",
				})
			}
			if passwordArchivePattern.MatchString(variant) {
				findings = append(findings, Finding{
					ID:       "PASSWORD_PROTECTED_ARCHIVE",
					Severity: "high",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "password-protected archive instruction detected",
				})
			}
			if rawHTMLPattern.MatchString(variant) {
				findings = append(findings, Finding{
					ID:       "RAW_HTML_MARKUP",
					Severity: "medium",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "raw HTML markup detected in markdown content",
				})
			}
			findings = append(findings, classifyMarkdownLinkSpoofing(variant, target.Relative, lineNum)...)
		}
	}

	return deduplicateFindings(findings), nil
}

func hasPromptOverrideApproximatePhrase(line string) bool {
	tokens := tokenizeWords(line)
	if len(tokens) == 0 {
		return false
	}
	for _, phrase := range promptOverridePhrases {
		if len(tokens) < len(phrase) {
			continue
		}
		for i := 0; i <= len(tokens)-len(phrase); i++ {
			if matchesApproximatePhrase(tokens[i:i+len(phrase)], phrase) {
				return true
			}
		}
	}
	return false
}

func matchesApproximatePhrase(window []string, phrase []string) bool {
	if len(window) != len(phrase) {
		return false
	}
	for i := range phrase {
		if !isApproxWordMatch(window[i], phrase[i]) {
			return false
		}
	}
	return true
}

func isApproxWordMatch(in string, want string) bool {
	if in == want {
		return true
	}
	if len(in) < 3 || len(want) < 3 {
		return false
	}
	if isTypoglycemiaVariant(in, want) {
		return true
	}
	return boundedLevenshteinDistance(in, want, 1) <= 1
}

func isTypoglycemiaVariant(in string, want string) bool {
	inRunes := []rune(in)
	wantRunes := []rune(want)
	if len(inRunes) != len(wantRunes) || len(inRunes) < 4 {
		return false
	}
	if inRunes[0] != wantRunes[0] || inRunes[len(inRunes)-1] != wantRunes[len(wantRunes)-1] {
		return false
	}
	inMiddle := make(map[rune]int, len(inRunes))
	wantMiddle := make(map[rune]int, len(wantRunes))
	for i := 1; i < len(inRunes)-1; i++ {
		inMiddle[inRunes[i]]++
		wantMiddle[wantRunes[i]]++
	}
	if len(inMiddle) != len(wantMiddle) {
		return false
	}
	for r, count := range inMiddle {
		if wantMiddle[r] != count {
			return false
		}
	}
	return true
}

func boundedLevenshteinDistance(a string, b string, limit int) int {
	ra := []rune(a)
	rb := []rune(b)
	if absInt(len(ra)-len(rb)) > limit {
		return limit + 1
	}
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := 0; j <= len(rb); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		rowMin := curr[0]
		for j := 1; j <= len(rb); j++ {
			cost := 0
			if ra[i-1] != rb[j-1] {
				cost = 1
			}
			insertCost := curr[j-1] + 1
			deleteCost := prev[j] + 1
			replaceCost := prev[j-1] + cost
			best := minInt(insertCost, deleteCost)
			best = minInt(best, replaceCost)
			curr[j] = best
			if best < rowMin {
				rowMin = best
			}
		}
		if rowMin > limit {
			return limit + 1
		}
		prev, curr = curr, prev
	}
	if prev[len(rb)] > limit {
		return limit + 1
	}
	return prev[len(rb)]
}

func hasChmodExecChain(line string) bool {
	segments := splitCommandSegments(line)
	if len(segments) < 2 {
		return false
	}
	targets := make(map[string]struct{}, 2)
	for _, segment := range segments {
		fields := strings.Fields(strings.TrimSpace(segment))
		if len(fields) == 0 {
			continue
		}

		if target := findChmodExecutableTarget(fields); target != "" {
			targets[target] = struct{}{}
			continue
		}

		execTarget := findExecutedLocalTarget(fields)
		if execTarget == "" {
			continue
		}
		if _, ok := targets[execTarget]; ok {
			return true
		}
	}
	return false
}

func splitCommandSegments(line string) []string {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	replacer := strings.NewReplacer("&&", ";", "||", ";")
	normalized := replacer.Replace(line)
	raw := strings.Split(normalized, ";")
	out := make([]string, 0, len(raw))
	for _, segment := range raw {
		trimmed := strings.TrimSpace(segment)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func findChmodExecutableTarget(fields []string) string {
	start := 0
	if fields[start] == "sudo" {
		start++
		if start >= len(fields) {
			return ""
		}
	}
	if fields[start] != "chmod" {
		return ""
	}
	for i := start + 1; i < len(fields)-1; i++ {
		if strings.Contains(fields[i], "+x") {
			return normalizeExecPath(fields[i+1])
		}
	}
	return ""
}

func findExecutedLocalTarget(fields []string) string {
	start := 0
	if fields[start] == "sudo" {
		start++
		if start >= len(fields) {
			return ""
		}
	}
	cmd := strings.ToLower(fields[start])
	switch cmd {
	case "chmod":
		return ""
	case "sh", "bash", "zsh", "pwsh", "powershell", "python", "node":
		if start+1 >= len(fields) {
			return ""
		}
		return normalizeExecPath(fields[start+1])
	default:
		return normalizeExecPath(fields[start])
	}
}

func normalizeExecPath(token string) string {
	clean := strings.TrimSpace(token)
	clean = strings.Trim(clean, `"'`)
	clean = strings.TrimPrefix(clean, "./")
	clean = strings.TrimPrefix(clean, ".\\")
	clean = strings.TrimSuffix(clean, ",")
	clean = strings.TrimSuffix(clean, ")")
	clean = strings.TrimSuffix(clean, "]")
	if clean == "" {
		return ""
	}
	if strings.HasPrefix(clean, "-") {
		return ""
	}
	if strings.Contains(clean, "://") {
		return ""
	}
	if strings.ContainsRune(clean, '$') {
		return ""
	}
	return clean
}

func hasHomeConfigWrite(line string) bool {
	lower := strings.ToLower(line)
	if hasCrontabWrite(lower) {
		return true
	}
	if !containsAnyString(lower, homeConfigPathHints) {
		return false
	}
	if strings.Contains(lower, ">>") || strings.Contains(lower, ">|") {
		return true
	}
	if strings.Contains(lower, "| tee") || strings.Contains(lower, "tee -a") {
		return true
	}
	if strings.Contains(lower, " cp ") || strings.HasPrefix(strings.TrimSpace(lower), "cp ") {
		return true
	}
	if strings.Contains(lower, " mv ") || strings.HasPrefix(strings.TrimSpace(lower), "mv ") {
		return true
	}
	if strings.Contains(lower, " install ") || strings.HasPrefix(strings.TrimSpace(lower), "install ") {
		return true
	}
	return false
}

func hasCrontabWrite(line string) bool {
	if strings.Contains(line, "| crontab") || strings.Contains(line, "|crontab") {
		return true
	}
	return strings.Contains(line, "crontab -e")
}

func containsAnyString(s string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func hasSecretExfilLine(line string) bool {
	lower := strings.ToLower(line)
	if !containsAnyString(lower, secretPathHints) {
		return false
	}
	if !secretExfilNetworkCommand.MatchString(lower) {
		return false
	}
	if !strings.Contains(lower, "http://") && !strings.Contains(lower, "https://") {
		return false
	}
	if strings.Contains(lower, "| curl") || strings.Contains(lower, "|curl") || strings.Contains(lower, "| wget") || strings.Contains(lower, "|wget") {
		return true
	}
	sendHints := []string{
		"-d ",
		"--data",
		"--upload-file",
		"requests.post",
		"invoke-restmethod",
		"invoke-webrequest",
		"-f ",
	}
	return containsAnyString(lower, sendHints)
}

func hasBashWildcardPermission(line string) bool {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "bash") {
		return false
	}
	for _, pattern := range bashWildcardPermissionPatterns {
		if pattern.MatchString(line) {
			return true
		}
	}
	return false
}

func tokenizeWords(line string) []string {
	normalized := strings.ToLower(strings.TrimSpace(line))
	if normalized == "" {
		return nil
	}
	words := strings.FieldsFunc(normalized, func(r rune) bool {
		return !unicode.IsLetter(r)
	})
	out := make([]string, 0, len(words))
	for _, word := range words {
		if word == "" {
			continue
		}
		out = append(out, word)
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

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

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}

func isUnpinnedRuntimeToolLine(line string) bool {
	lowerLine := strings.ToLower(strings.TrimSpace(line))
	if isRemoteScriptImportLine(lowerLine) {
		return true
	}

	fields := strings.Fields(lowerLine)
	if len(fields) == 0 {
		return false
	}

	for i := 0; i < len(fields); i++ {
		token := normalizeLauncherToken(fields[i])
		if token == "corepack" {
			launcher, launcherIndex, ok := nextNonFlagFieldWithIndex(fields, i+1)
			if !ok {
				continue
			}
			launcher = normalizeLauncherToken(launcher)
			if isUnpinnedLauncherCommand(fields, launcher, launcherIndex) {
				return true
			}
			continue
		}

		if isUnpinnedLauncherCommand(fields, token, i) {
			return true
		}
	}

	return false
}

func normalizeLauncherToken(token string) string {
	token = strings.TrimSpace(strings.ToLower(token))
	if token == "" {
		return token
	}
	for _, launcher := range []string{"npx", "uvx", "bunx", "pnpm", "yarn", "npm"} {
		prefix := launcher + "@"
		if strings.HasPrefix(token, prefix) && len(token) > len(prefix) {
			return launcher
		}
	}
	return token
}

func isUnpinnedLauncherCommand(fields []string, token string, tokenIndex int) bool {
	switch token {
	case "npx", "uvx", "bunx":
		packageRef, ok := nextNonFlagField(fields, tokenIndex+1)
		if !ok {
			return false
		}
		return isUnpinnedPackageRef(packageRef)
	case "pnpm", "yarn":
		subcommand, subcommandIndex, ok := nextNonFlagFieldWithIndex(fields, tokenIndex+1)
		if !ok || subcommand != "dlx" {
			return false
		}
		packageRef, ok := nextNonFlagField(fields, subcommandIndex+1)
		if !ok {
			return false
		}
		return isUnpinnedPackageRef(packageRef)
	case "npm":
		subcommand, subcommandIndex, ok := nextNonFlagFieldWithIndex(fields, tokenIndex+1)
		if !ok || subcommand != "exec" {
			return false
		}
		packageRef, ok := nextNonFlagField(fields, subcommandIndex+1)
		if !ok {
			return false
		}
		if packageRef == "--" {
			packageRef, ok = nextNonFlagField(fields, subcommandIndex+2)
			if !ok {
				return false
			}
		}
		return isUnpinnedPackageRef(packageRef)
	case "go":
		if tokenIndex+2 >= len(fields) || fields[tokenIndex+1] != "run" {
			return false
		}
		for j := tokenIndex + 2; j < len(fields); j++ {
			part := fields[j]
			if strings.HasPrefix(part, "-") {
				continue
			}
			return isUnpinnedGoRunTarget(part)
		}
		return false
	default:
		return false
	}
}

func isUnpinnedGoRunTarget(target string) bool {
	if target == "" {
		return false
	}
	if strings.HasSuffix(target, ".go") {
		return false
	}
	if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") || strings.HasPrefix(target, "/") {
		return false
	}
	if strings.HasPrefix(target, ".\\") || strings.HasPrefix(target, "..\\") || strings.HasPrefix(target, "\\") {
		return false
	}

	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		if len(parts) != 2 {
			return false
		}
		version := strings.TrimSpace(parts[1])
		return !isPinnedGoModuleVersion(version)
	}

	// Remote Go module/package paths conventionally include a dot in the first segment.
	firstSegment := target
	if slash := strings.Index(firstSegment, "/"); slash >= 0 {
		firstSegment = firstSegment[:slash]
	}
	return strings.Contains(firstSegment, ".")
}

func isPinnedGoModuleVersion(version string) bool {
	if version == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(version))
	if lower == "latest" {
		return false
	}
	if goSemverExactPattern.MatchString(lower) {
		return true
	}
	if goPseudoVersionPattern.MatchString(lower) {
		return true
	}
	if hexCommitRefPattern.MatchString(lower) {
		return true
	}
	return false
}

func isRemoteScriptImportLine(lowerLine string) bool {
	if remoteScriptImportPattern.MatchString(lowerLine) {
		return true
	}
	return remoteDenoRunPattern.MatchString(lowerLine)
}

func isUnpinnedPackageRef(ref string) bool {
	if ref == "" {
		return false
	}

	if strings.HasPrefix(ref, "@") {
		lastAt := strings.LastIndex(ref, "@")
		if lastAt <= 0 || lastAt == len(ref)-1 {
			return true
		}
		return !isPinnedPackageVersion(ref[lastAt+1:])
	}

	parts := strings.SplitN(ref, "@", 2)
	if len(parts) == 1 {
		return true
	}
	return !isPinnedPackageVersion(parts[1])
}

func isPinnedPackageVersion(version string) bool {
	if version == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(version))
	if lower == "latest" {
		return false
	}
	// Treat exact semver as pinned for package launchers. Dist-tags and ranges
	// like "next", "^1.2.3", or "~1.2.3" remain floating.
	return goSemverExactPattern.MatchString(lower)
}

func nextNonFlagField(fields []string, start int) (string, bool) {
	value, _, ok := nextNonFlagFieldWithIndex(fields, start)
	return value, ok
}

func nextNonFlagFieldWithIndex(fields []string, start int) (string, int, bool) {
	for i := start; i < len(fields); i++ {
		if strings.HasPrefix(fields[i], "-") {
			continue
		}
		return fields[i], i, true
	}
	return "", -1, false
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
