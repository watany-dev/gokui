package app

import (
	"fmt"
	"strings"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func parseVetArgs(args []string) (input string, format string, profile string, profileSet bool, err error) {
	format = "human"
	profile = policypkg.ProfileStrict.String()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--format" {
			if i+1 >= len(args) {
				return "", "", "", false, fmt.Errorf("missing value for --format")
			}
			format = args[i+1]
			i++
			continue
		}
		if arg == "--profile" {
			if i+1 >= len(args) {
				return "", "", "", false, fmt.Errorf("missing value for --profile")
			}
			profile = args[i+1]
			profileSet = true
			i++
			continue
		}
		if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
			continue
		}
		if strings.HasPrefix(arg, "--profile=") {
			profile = strings.TrimPrefix(arg, "--profile=")
			profileSet = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return "", "", "", false, fmt.Errorf("unknown vet option: %s", arg)
		}
		if input != "" {
			return "", "", "", false, fmt.Errorf("vet accepts exactly one source")
		}
		input = arg
	}

	if input == "" {
		return "", "", "", false, fmt.Errorf("vet source is required")
	}
	if !supportsReviewCommandFormat(format) {
		return "", "", "", false, fmt.Errorf("unsupported vet format: %s", format)
	}
	return input, format, profile, profileSet, nil
}
