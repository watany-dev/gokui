package app

import "fmt"

func extractInspectSourceArg(args []string) string {
	return firstPositionalArg(args, "--format")
}

func parseInspectArgs(args []string) (input string, format string, err error) {
	format = defaultCommandFormat()
	parser := commandArgParser{
		valueHandlers: []valueFlagHandler{
			{flag: "--format", set: func(value string) { format = value }},
		},
		handlePositional: func(arg string) error { return parseSingleSourcePositionalArg(&input, "inspect", arg) },
	}
	for i := 0; i < len(args); i++ {
		next, err := parser.parse(args, i)
		if err != nil {
			return "", "", err
		}
		i = next
	}

	if input == "" {
		return "", "", fmt.Errorf("inspect source is required")
	}
	if !supportsReviewCommandFormat(format) {
		return "", "", fmt.Errorf("unsupported inspect format: %s", format)
	}
	return input, format, nil
}
