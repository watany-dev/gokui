package app

import "fmt"

func extractLockVerifyPathArg(args []string) string {
	if path := firstPositionalArg(args, "--format"); path != "" {
		return path
	}
	return "."
}

func parseLockVerifyArgs(args []string) (lockVerifyArgs, error) {
	out := lockVerifyArgs{
		Path:   ".",
		Format: defaultCommandFormat(),
	}
	for i := 0; i < len(args); i++ {
		next, err := parseCommandArg(args, i,
			[]valueFlagHandler{
				{flag: "--format", set: func(value string) { out.Format = value }},
			},
			nil,
			func(arg string) error { return parseOptionalPathPositionalArg(&out.Path, ".", "lock verify", arg) },
		)
		if err != nil {
			return lockVerifyArgs{}, err
		}
		i = next
	}
	if !supportsCommandFormat(out.Format) {
		return lockVerifyArgs{}, fmt.Errorf("unsupported lock verify format: %s", out.Format)
	}
	return out, nil
}
