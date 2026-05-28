package app

import (
	"fmt"
	"strings"
)

func extractUpdateTargetArg(args []string) string {
	return flagValueArg(args, "--target", "codex")
}

func parseUpdateArgs(args []string) (updateArgs, error) {
	out := updateArgs{
		Target: "codex",
		Format: defaultCommandFormat(),
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if next, ok, err := parseValueFlagHandlers(args, i,
			valueFlagHandler{flag: "--format", set: func(value string) { out.Format = value }},
			valueFlagHandler{flag: "--target", set: func(value string) { out.Target = value }},
		); ok {
			if err != nil {
				return updateArgs{}, err
			}
			i = next
			continue
		}
		switch {
		case arg == "--dry-run":
			out.DryRun = true
		case strings.HasPrefix(arg, "-"):
			return updateArgs{}, unknownOptionError("update", arg)
		default:
			return updateArgs{}, positionalArgNotAcceptedError("update", arg)
		}
	}

	if !out.DryRun {
		return updateArgs{}, fmt.Errorf("update currently requires --dry-run")
	}
	if !supportsCommandFormat(out.Format) {
		return updateArgs{}, fmt.Errorf("unsupported update format: %s", out.Format)
	}
	return out, nil
}
