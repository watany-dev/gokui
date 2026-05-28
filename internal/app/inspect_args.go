package app

import (
	"fmt"
	"strings"
)

func extractInspectSourceArg(args []string) string {
	return firstPositionalArg(args, "--format")
}

func parseInspectArgs(args []string) (input string, format string, err error) {
	format = defaultCommandFormat()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if next, ok, err := parseValueFlagHandlers(args, i,
			valueFlagHandler{flag: "--format", set: func(value string) { format = value }},
		); ok {
			if err != nil {
				return "", "", err
			}
			i = next
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return "", "", unknownOptionError("inspect", arg)
		}
		if err := setSingleSourceArg(&input, "inspect", arg); err != nil {
			return "", "", err
		}
	}

	if input == "" {
		return "", "", fmt.Errorf("inspect source is required")
	}
	if !supportsReviewCommandFormat(format) {
		return "", "", fmt.Errorf("unsupported inspect format: %s", format)
	}
	return input, format, nil
}
