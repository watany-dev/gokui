package app

import (
	"fmt"
	"strings"
)

func extractFetchSourceArg(args []string) string {
	return firstPositionalArg(args, "--out", "--format")
}

func parseFetchArgs(args []string) (fetchArgs, error) {
	out := fetchArgs{Format: "human"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--out":
			if i+1 >= len(args) {
				return fetchArgs{}, fmt.Errorf("missing value for --out")
			}
			out.Out = args[i+1]
			i++
		case strings.HasPrefix(arg, "--out="):
			out.Out = strings.TrimPrefix(arg, "--out=")
		case arg == "--format":
			if i+1 >= len(args) {
				return fetchArgs{}, fmt.Errorf("missing value for --format")
			}
			out.Format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			out.Format = strings.TrimPrefix(arg, "--format=")
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
