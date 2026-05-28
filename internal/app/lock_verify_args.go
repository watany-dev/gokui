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
			return lockVerifyArgs{}, fmt.Errorf("unknown lock verify option: %s", arg)
		default:
			if out.Path != "." {
				return lockVerifyArgs{}, fmt.Errorf("lock verify accepts at most one path")
			}
			out.Path = arg
		}
	}
	if !supportsCommandFormat(out.Format) {
		return lockVerifyArgs{}, fmt.Errorf("unsupported lock verify format: %s", out.Format)
	}
	return out, nil
}
