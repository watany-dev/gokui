package app

import (
	"fmt"
	"strings"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func argsRequestFormat(args []string, format string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) && args[i+1] == format {
			return true
		}
		if strings.HasPrefix(args[i], "--format=") && strings.TrimPrefix(args[i], "--format=") == format {
			return true
		}
	}
	return false
}

func firstPositionalArg(args []string, valueFlags ...string) string {
	skipValue := make(map[string]struct{}, len(valueFlags))
	for _, flag := range valueFlags {
		skipValue[flag] = struct{}{}
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if _, ok := skipValue[arg]; ok {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--") {
			if flag, _, ok := strings.Cut(arg, "="); ok {
				if _, skip := skipValue[flag]; skip {
					continue
				}
			}
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

func flagValueArg(args []string, flag string, fallback string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == flag && i+1 < len(args) {
			return args[i+1]
		}
		if value, ok := strings.CutPrefix(args[i], flag+"="); ok {
			return value
		}
	}
	return fallback
}

func extractInspectSourceArg(args []string) string {
	return firstPositionalArg(args, "--format")
}

func parseInspectArgs(args []string) (input string, format string, err error) {
	format = "human"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--format" {
			if i+1 >= len(args) {
				return "", "", fmt.Errorf("missing value for --format")
			}
			format = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return "", "", fmt.Errorf("unknown inspect option: %s", arg)
		}
		if input != "" {
			return "", "", fmt.Errorf("inspect accepts exactly one source")
		}
		input = arg
	}

	if input == "" {
		return "", "", fmt.Errorf("inspect source is required")
	}
	if format != "human" && format != "json" && format != "sarif" && format != "compact" && format != "review-json" {
		return "", "", fmt.Errorf("unsupported inspect format: %s", format)
	}
	return input, format, nil
}

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
	if format != "human" && format != "json" && format != "sarif" && format != "compact" && format != "review-json" {
		return "", "", "", false, fmt.Errorf("unsupported vet format: %s", format)
	}
	return input, format, profile, profileSet, nil
}
