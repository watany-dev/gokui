package app

import "strings"

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

func supportsCommandFormat(format string) bool {
	return format == "human" || format == "json" || format == "sarif" || format == "compact"
}

func supportsReviewCommandFormat(format string) bool {
	return supportsCommandFormat(format) || format == "review-json"
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
