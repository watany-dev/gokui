package app

import (
	"fmt"
	"strings"
)

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
		if formatValue, next, ok, err := parseFormatArg(args, i); ok {
			if err != nil {
				return lockVerifyArgs{}, err
			}
			out.Format = formatValue
			i = next
			continue
		}
		switch {
		case strings.HasPrefix(arg, "-"):
			return lockVerifyArgs{}, unknownOptionError("lock verify", arg)
		default:
			if err := setOptionalPathArg(&out.Path, ".", "lock verify", arg); err != nil {
				return lockVerifyArgs{}, err
			}
		}
	}
	if !supportsCommandFormat(out.Format) {
		return lockVerifyArgs{}, fmt.Errorf("unsupported lock verify format: %s", out.Format)
	}
	return out, nil
}
