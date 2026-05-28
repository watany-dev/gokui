package app

import (
	"fmt"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func parseVetArgs(args []string) (input string, format string, profile string, profileSet bool, err error) {
	format = defaultCommandFormat()
	profile = policypkg.ProfileStrict.String()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if next, ok, err := parseValueFlagHandlers(args, i,
			valueFlagHandler{flag: "--format", set: func(value string) { format = value }},
			valueFlagHandler{flag: "--profile", set: func(value string) {
				profile = value
				profileSet = true
			}},
		); ok {
			if err != nil {
				return "", "", "", false, err
			}
			i = next
			continue
		}
		if err := parseSingleSourcePositionalArg(&input, "vet", arg); err != nil {
			return "", "", "", false, err
		}
	}

	if input == "" {
		return "", "", "", false, fmt.Errorf("vet source is required")
	}
	if !supportsReviewCommandFormat(format) {
		return "", "", "", false, fmt.Errorf("unsupported vet format: %s", format)
	}
	return input, format, profile, profileSet, nil
}
