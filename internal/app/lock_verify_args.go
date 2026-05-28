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
		arg := args[i]
		if next, ok, err := parseValueFlagHandlers(args, i,
			valueFlagHandler{flag: "--format", set: func(value string) { out.Format = value }},
		); ok {
			if err != nil {
				return lockVerifyArgs{}, err
			}
			i = next
			continue
		}
		if err := parseOptionalPathPositionalArg(&out.Path, ".", "lock verify", arg); err != nil {
			return lockVerifyArgs{}, err
		}
	}
	if !supportsCommandFormat(out.Format) {
		return lockVerifyArgs{}, fmt.Errorf("unsupported lock verify format: %s", out.Format)
	}
	return out, nil
}
