package rule

import (
	"regexp"
	"strings"
)

var (
	idPrefixPattern   = regexp.MustCompile(`^([A-Z][A-Z0-9_]+):\s`)
	idAnywherePattern = regexp.MustCompile(`(?:^|[^A-Z0-9_])([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+):\s`)
)

// InferIDFromMessage extracts a leading RULE_ID: marker from an error message.
func InferIDFromMessage(message string) string {
	match := idPrefixPattern.FindStringSubmatch(strings.TrimSpace(message))
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

// InferIDForJSONError extracts a rule ID marker from messages embedded in JSON errors.
func InferIDForJSONError(message string) string {
	if id := InferIDFromMessage(message); id != "" {
		return id
	}
	match := idAnywherePattern.FindStringSubmatch(message)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}
