package app

import (
	"fmt"
	"strings"
)

func extractFetchSourceArg(args []string) string {
	return firstPositionalArg(args, "--out", "--format")
}

func parseFetchArgs(args []string) (fetchArgs, error) {
	out := fetchArgs{Format: defaultCommandFormat()}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if formatValue, next, ok, err := parseFormatArg(args, i); ok {
			if err != nil {
				return fetchArgs{}, err
			}
			out.Format = formatValue
			i = next
			continue
		}
		if outValue, next, ok, err := parseValueFlagArg(args, i, "--out"); ok {
			if err != nil {
				return fetchArgs{}, err
			}
			out.Out = outValue
			i = next
			continue
		}
		switch {
		case strings.HasPrefix(arg, "-"):
			return fetchArgs{}, fmt.Errorf("unknown fetch option: %s", arg)
		default:
			if out.Source != "" {
				return fetchArgs{}, fmt.Errorf("fetch accepts exactly one source")
			}
			out.Source = arg
		}
	}

	if out.Source == "" {
		return fetchArgs{}, fmt.Errorf("fetch source is required")
	}
	if strings.TrimSpace(out.Out) == "" {
		return fetchArgs{}, fmt.Errorf("fetch output root is required (--out)")
	}
	if !supportsCommandFormat(out.Format) {
		return fetchArgs{}, fmt.Errorf("unsupported fetch format: %s", out.Format)
	}
	return out, nil
}
