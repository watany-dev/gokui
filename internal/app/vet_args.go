package app

import (
	"fmt"
	"strings"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func parseVetArgs(args []string) (input string, format string, profile string, profileSet bool, err error) {
	format = defaultCommandFormat()
	profile = policypkg.ProfileStrict.String()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if formatValue, next, ok, formatErr := parseFormatArg(args, i); ok {
			if formatErr != nil {
				return "", "", "", false, formatErr
			}
			format = formatValue
			i = next
			continue
		}
		if profileValue, next, ok, profileErr := parseValueFlagArg(args, i, "--profile"); ok {
			if profileErr != nil {
				return "", "", "", false, profileErr
			}
			profile = profileValue
			profileSet = true
			i = next
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return "", "", "", false, unknownOptionError("vet", arg)
		}
		if err := setSingleSourceArg(&input, "vet", arg); err != nil {
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
