package app

import (
	"fmt"
	"sort"
	"strings"
)

func parseInstallArgs(args []string) (installArgs, error) {
	out := installArgs{Profile: "strict", Format: defaultCommandFormat()}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--target":
			if i+1 >= len(args) {
				return installArgs{}, fmt.Errorf("missing value for --target")
			}
			out.Target = args[i+1]
			i++
		case strings.HasPrefix(arg, "--target="):
			out.Target = strings.TrimPrefix(arg, "--target=")
		case arg == "--profile":
			if i+1 >= len(args) {
				return installArgs{}, fmt.Errorf("missing value for --profile")
			}
			out.Profile = args[i+1]
			out.ProfileSet = true
			i++
		case strings.HasPrefix(arg, "--profile="):
			out.Profile = strings.TrimPrefix(arg, "--profile=")
			out.ProfileSet = true
		case arg == "--format":
			if i+1 >= len(args) {
				return installArgs{}, fmt.Errorf("missing value for --format")
			}
			out.Format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			out.Format = strings.TrimPrefix(arg, "--format=")
		case arg == "--override":
			if i+1 >= len(args) {
				return installArgs{}, fmt.Errorf("missing value for --override")
			}
			out.Overrides = append(out.Overrides, args[i+1])
			i++
		case strings.HasPrefix(arg, "--override="):
			out.Overrides = append(out.Overrides, strings.TrimPrefix(arg, "--override="))
		case strings.HasPrefix(arg, "-"):
			return installArgs{}, fmt.Errorf("unknown install option: %s", arg)
		default:
			if out.Source != "" {
				return installArgs{}, fmt.Errorf("install accepts exactly one source")
			}
			out.Source = arg
		}
	}

	if out.Source == "" {
		return installArgs{}, fmt.Errorf("install source is required")
	}
	if out.Target == "" {
		return installArgs{}, fmt.Errorf("install target is required")
	}
	if !supportsCommandFormat(out.Format) {
		return installArgs{}, fmt.Errorf("unsupported install format: %s", out.Format)
	}
	if len(out.Overrides) > 0 {
		seen := make(map[string]struct{}, len(out.Overrides))
		normalized := make([]string, 0, len(out.Overrides))
		for _, override := range out.Overrides {
			ruleID := strings.TrimSpace(override)
			if !errorCodePattern.MatchString(ruleID) {
				return installArgs{}, fmt.Errorf("invalid override rule id: %s", override)
			}
			if _, ok := seen[ruleID]; ok {
				continue
			}
			seen[ruleID] = struct{}{}
			normalized = append(normalized, ruleID)
		}
		sort.Strings(normalized)
		out.Overrides = normalized
	}
	return out, nil
}

func extractInstallSourceArg(args []string) string {
	return firstPositionalArg(args, "--target", "--profile", "--format")
}

func extractInstallTargetArg(args []string) string {
	return flagValueArg(args, "--target", "")
}

func extractInstallProfileArg(args []string) string {
	return flagValueArg(args, "--profile", "strict")
}
