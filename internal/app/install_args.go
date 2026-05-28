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
		if next, ok, err := parseValueFlagHandlers(args, i,
			valueFlagHandler{flag: "--format", set: func(value string) { out.Format = value }},
			valueFlagHandler{flag: "--target", set: func(value string) { out.Target = value }},
			valueFlagHandler{flag: "--profile", set: func(value string) {
				out.Profile = value
				out.ProfileSet = true
			}},
			valueFlagHandler{flag: "--override", set: func(value string) {
				out.Overrides = append(out.Overrides, value)
			}},
		); ok {
			if err != nil {
				return installArgs{}, err
			}
			i = next
			continue
		}
		if err := parseSingleSourcePositionalArg(&out.Source, "install", arg); err != nil {
			return installArgs{}, err
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
