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
	parser := commandArgParser{
		valueHandlers: []valueFlagHandler{
			formatValueFlag(&out.Format),
			{flag: "--out", set: func(value string) { out.Out = value }},
		},
		handlePositional: singleSourcePositional(&out.Source, "fetch"),
	}
	for i := 0; i < len(args); i++ {
		next, err := parser.parse(args, i)
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
