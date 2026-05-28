package scan

import (
	"strings"
	"unicode"
)

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

func hasEncodedCommandExecLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return false
	}
	fields := strings.Fields(lower)
	if len(fields) == 0 {
		return false
	}

	sawPowerShell := false
	for _, field := range fields {
		token := sanitizeRuntimeToken(field)
		switch token {
		case "powershell", "pwsh", "powershell.exe", "pwsh.exe":
			sawPowerShell = true
			continue
		}
		if !sawPowerShell {
			continue
		}
		if isEncodedCommandFlagToken(token) {
			return true
		}
	}
	return false
}

func isEncodedCommandFlagToken(token string) bool {
	if token == "" {
		return false
	}
	trimmed := strings.TrimLeft(token, "-/")
	switch {
	case trimmed == "encodedcommand", trimmed == "enc":
		return true
	case strings.HasPrefix(trimmed, "encodedcommand:"), strings.HasPrefix(trimmed, "encodedcommand="):
		return true
	case strings.HasPrefix(trimmed, "enc:"), strings.HasPrefix(trimmed, "enc="):
		return true
	default:
		return false
	}
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
