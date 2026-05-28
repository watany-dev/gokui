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
		next, err := parseCommandArg(args, i,
			[]valueFlagHandler{
				{flag: "--format", set: func(value string) { out.Format = value }},
				{flag: "--out", set: func(value string) { out.Out = value }},
			},
			nil,
			func(arg string) error { return parseSingleSourcePositionalArg(&out.Source, "fetch", arg) },
		)
		if err != nil {
			return fetchArgs{}, err
		}
		i = next
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
