package app

import (
	"fmt"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func parseVetArgs(args []string) (input string, format string, profile string, profileSet bool, err error) {
	format = defaultCommandFormat()
	profile = policypkg.ProfileStrict.String()
	parser := commandArgParser{
		valueHandlers: []valueFlagHandler{
			{flag: "--format", set: func(value string) { format = value }},
			{flag: "--profile", set: func(value string) {
				profile = value
				profileSet = true
			}},
		},
		handlePositional: func(arg string) error { return parseSingleSourcePositionalArg(&input, "vet", arg) },
	}
	for i := 0; i < len(args); i++ {
		next, err := parser.parse(args, i)
		if err != nil {
			return "", "", "", false, err
		}
		i = next
	}

	if input == "" {
		return "", "", "", false, fmt.Errorf("vet source is required")
	}
	if !supportsReviewCommandFormat(format) {
		return "", "", "", false, fmt.Errorf("unsupported vet format: %s", format)
	}
	return input, format, profile, profileSet, nil
}
