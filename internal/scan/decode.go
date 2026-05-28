package scan

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/rule"
)

func scanDecodedVariantThreatFindings(line string, target scanTarget, lineNum int, depth int) []Finding {
	if depth >= maxDecodedRecursionDepth {
		return nil
	}
	candidates := extractEncodedCandidates(line)
	if len(candidates) == 0 {
		return nil
	}

	findings := make([]Finding, 0, 4)
	for _, candidate := range candidates {
		decoded, ok := decodeCandidatePayload(candidate)
		if !ok || len(decoded) == 0 || len(decoded) > maxDecodedArtifactBytes {
			continue
		}
		if !isLikelyTextPayload(decoded) {
			continue
		}

		decodedText := strings.ReplaceAll(string(decoded), "\r\n", "\n")
		for _, decodedLine := range strings.Split(decodedText, "\n") {
			if strings.TrimSpace(decodedLine) == "" {
				continue
			}
			normalized, changed := normalizeLineNFKC(decodedLine)
			if changed {
				findings = append(findings, newFinding(rule.NFKCChangesText, target.Relative, lineNum, "Unicode compatibility normalization changes text"))
			}
			findings = append(findings, classifyUnicodeThreats(decodedLine, target.Relative, lineNum)...)
			for _, variant := range lineVariants(decodedLine, normalized, changed) {
				findings = append(findings, scanVariantThreatFindings(variant, target, lineNum)...)
				findings = append(findings, scanDecodedVariantThreatFindings(variant, target, lineNum, depth+1)...)
			}
		}
	}
	return findings
}

func extractEncodedCandidates(line string) []encodedCandidate {
	fields := strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '"', '\'', '`', ',', ';', ':', '(', ')', '[', ']', '{', '}', '<', '>', '|':
			return true
		default:
			return false
		}
	})
	if len(fields) == 0 {
		return nil
	}

	candidates := make([]encodedCandidate, 0, minInt(len(fields), maxDecodedCandidatesPerLine))
	for _, raw := range fields {
		token := sanitizeRuntimeToken(raw)
		if token == "" {
			continue
		}
		token = strings.TrimPrefix(strings.ToLower(token), "0x")
		if len(token) >= minHexCandidateLength && len(token)%2 == 0 && isHexToken(token) {
			candidates = append(candidates, encodedCandidate{kind: "hex", value: token})
			if len(candidates) >= maxDecodedCandidatesPerLine {
				break
			}
			continue
		}

		token = sanitizeRuntimeToken(raw)
		if len(token) >= minBase64CandidateLength && isBase64Token(token) {
			candidates = append(candidates, encodedCandidate{kind: "base64", value: token})
			if len(candidates) >= maxDecodedCandidatesPerLine {
				break
			}
		}
	}
	return candidates
}

func decodeCandidatePayload(candidate encodedCandidate) ([]byte, bool) {
	switch candidate.kind {
	case "hex":
		decoded, err := hex.DecodeString(candidate.value)
		if err != nil {
			return nil, false
		}
		return decoded, true
	case "base64":
		token := strings.TrimSpace(candidate.value)
		decoded, err := base64.StdEncoding.DecodeString(token)
		if err == nil {
			return decoded, true
		}
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(token, "="))
		if err == nil {
			return decoded, true
		}
		decoded, err = base64.URLEncoding.DecodeString(token)
		if err == nil {
			return decoded, true
		}
		decoded, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(token, "="))
		if err == nil {
			return decoded, true
		}
		return nil, false
	default:
		return nil, false
	}
}

func isLikelyTextPayload(decoded []byte) bool {
	if len(decoded) == 0 {
		return false
	}
	if !utf8.Valid(decoded) {
		return false
	}
	printable := 0
	total := 0
	for _, r := range string(decoded) {
		total++
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && !unicode.IsControl(r)) {
			printable++
		}
	}
	if total == 0 {
		return false
	}
	return printable*100/total >= 80
}

func isHexToken(token string) bool {
	for i := 0; i < len(token); i++ {
		c := token[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

func isBase64Token(token string) bool {
	if token == "" {
		return false
	}
	paddingStart := -1
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '-' || c == '_':
		case c == '=':
			if paddingStart < 0 {
				paddingStart = i
			}
		default:
			return false
		}
		if paddingStart >= 0 && c != '=' {
			return false
		}
	}
	return true
}
