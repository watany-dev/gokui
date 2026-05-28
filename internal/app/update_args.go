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
		Format: "human",
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--dry-run":
			out.DryRun = true
		case arg == "--target":
			if i+1 >= len(args) {
				return updateArgs{}, fmt.Errorf("missing value for --target")
			}
			out.Target = args[i+1]
			i++
		case strings.HasPrefix(arg, "--target="):
			out.Target = strings.TrimPrefix(arg, "--target=")
		case arg == "--format":
			if i+1 >= len(args) {
				return updateArgs{}, fmt.Errorf("missing value for --format")
			}
			out.Format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			out.Format = strings.TrimPrefix(arg, "--format=")
		case strings.HasPrefix(arg, "-"):
			return updateArgs{}, fmt.Errorf("unknown update option: %s", arg)
		default:
			return updateArgs{}, fmt.Errorf("update does not accept positional arguments: %s", arg)
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
