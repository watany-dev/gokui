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
		if next, ok, err := parseValueFlagHandlers(args, i,
			valueFlagHandler{flag: "--format", set: func(value string) { out.Format = value }},
			valueFlagHandler{flag: "--out", set: func(value string) { out.Out = value }},
		); ok {
			if err != nil {
				return fetchArgs{}, err
			}
			i = next
			continue
		}
		switch {
		case strings.HasPrefix(arg, "-"):
			return fetchArgs{}, unknownOptionError("fetch", arg)
		default:
			if err := setSingleSourceArg(&out.Source, "fetch", arg); err != nil {
				return fetchArgs{}, err
			}
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
