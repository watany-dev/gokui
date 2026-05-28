package app

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	formatpkg "github.com/watany-dev/gokui/internal/cli/format"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

var errorCodePattern = regexp.MustCompile(`^[A-Z0-9_]+$`)

func emitStructuredError(format formatpkg.Format, writeJSON func(), writeSARIF func()) bool {
	switch format {
	case formatpkg.JSON:
		writeJSON()
		return true
	case formatpkg.SARIF:
		writeSARIF()
		return true
	default:
		return false
	}
}

func emitCommandStructuredError(format string, writeJSON func() int, writeSARIF func() int) bool {
	return emitStructuredError(formatpkg.Format(format),
		func() { _ = writeJSON() },
		func() { _ = writeSARIF() },
	)
}

func writeRequestedStructuredError(format formatpkg.Format, writeJSON func() int, writeSARIF func() int) (int, bool) {
	switch format {
	case formatpkg.JSON, formatpkg.ReviewJSON:
		return writeJSON(), true
	case formatpkg.SARIF:
		return writeSARIF(), true
	default:
		return 0, false
	}
}

func writeArgsParseError(format formatpkg.Format, stderr io.Writer, err error, writeJSON func() int, writeSARIF func() int) int {
	if code, ok := writeRequestedStructuredError(format, writeJSON, writeSARIF); ok {
		return code
	}
	_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
	return exitcode.Error.Int()
}

func normalizeStructuredErrorFields(errorCode string, ruleID string, message string, fallbackCode string) (string, string, string) {
	errorCode = normalizeJSONErrorCode(errorCode, fallbackCode)
	if ruleID == "" {
		ruleID = rulepkg.InferIDForJSONError(message)
	}
	return reportStatusError, errorCode, ruleID
}

func structuredErrorRuleID(errorCode string, ruleID string) string {
	if ruleID != "" {
		return ruleID
	}
	return errorCode
}

func writeJSONErrorReport(stdout io.Writer, stderr io.Writer, payload any, command string) int {
	return writeIndentedJSONLine(stdout, stderr, payload, fmt.Sprintf("failed to render %s error report", command))
}

func writeSARIFErrorReport(stdout io.Writer, stderr io.Writer, payload any, command string) int {
	return writeIndentedJSONLine(stdout, stderr, payload, fmt.Sprintf("failed to render %s sarif error report", command))
}

func writeIndentedJSONLine(stdout io.Writer, stderr io.Writer, payload any, renderError string) int {
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, renderError)
		return exitcode.Error.Int()
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return exitcode.Error.Int()
}

func normalizeJSONErrorCode(code string, fallback string) string {
	cleanedCode := strings.TrimSpace(code)
	if errorCodePattern.MatchString(cleanedCode) {
		return cleanedCode
	}
	cleanedFallback := strings.TrimSpace(fallback)
	if errorCodePattern.MatchString(cleanedFallback) {
		return cleanedFallback
	}
	return "UNKNOWN_ERROR"
}
