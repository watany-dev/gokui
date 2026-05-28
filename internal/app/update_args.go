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
		if formatValue, next, ok, err := parseFormatArg(args, i); ok {
			if err != nil {
				return updateArgs{}, err
			}
			out.Format = formatValue
			i = next
			continue
		}
		if targetValue, next, ok, err := parseValueFlagArg(args, i, "--target"); ok {
			if err != nil {
				return updateArgs{}, err
			}
			out.Target = targetValue
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
