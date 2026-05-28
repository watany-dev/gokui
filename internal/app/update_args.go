package app

import "fmt"

func extractUpdateTargetArg(args []string) string {
	return flagValueArg(args, "--target", "codex")
}

func parseUpdateArgs(args []string) (updateArgs, error) {
	out := updateArgs{
		Target: "codex",
		Format: defaultCommandFormat(),
	}

	for i := 0; i < len(args); i++ {
		next, err := parseCommandArg(args, i,
			[]valueFlagHandler{
				{flag: "--format", set: func(value string) { out.Format = value }},
				{flag: "--target", set: func(value string) { out.Target = value }},
			},
			[]boolFlagHandler{
				{flag: "--dry-run", set: func() { out.DryRun = true }},
			},
			func(arg string) error { return parseNoPositionalArg("update", arg) },
		)
		if err != nil {
			return updateArgs{}, err
		}
		i = next
	}

	if !out.DryRun {
		return updateArgs{}, fmt.Errorf("update currently requires --dry-run")
	}
	if !supportsCommandFormat(out.Format) {
		return updateArgs{}, fmt.Errorf("unsupported update format: %s", out.Format)
	}
	return out, nil
}
