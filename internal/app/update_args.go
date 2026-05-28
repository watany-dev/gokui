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
	parser := commandArgParser{
		valueHandlers: []valueFlagHandler{
			formatValueFlag(&out.Format),
			targetValueFlag(&out.Target),
		},
		boolHandlers: []boolFlagHandler{
			{flag: "--dry-run", set: func() { out.DryRun = true }},
		},
		handlePositional: noPositional("update"),
	}

	for i := 0; i < len(args); i++ {
		next, err := parser.parse(args, i)
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
