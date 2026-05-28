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
		if formatValue, next, ok, err := parseFormatArg(args, i); ok {
			if err != nil {
				return installArgs{}, err
			}
			out.Format = formatValue
			i = next
			continue
		}
		if targetValue, next, ok, err := parseValueFlagArg(args, i, "--target"); ok {
			if err != nil {
				return installArgs{}, err
			}
			out.Target = targetValue
			i = next
			continue
		}
		if profileValue, next, ok, err := parseValueFlagArg(args, i, "--profile"); ok {
			if err != nil {
				return installArgs{}, err
			}
			out.Profile = profileValue
			out.ProfileSet = true
			i = next
			continue
		}
		if overrideValue, next, ok, err := parseValueFlagArg(args, i, "--override"); ok {
			if err != nil {
				return installArgs{}, err
			}
			out.Overrides = append(out.Overrides, overrideValue)
			i = next
			continue
		}
		switch {
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
