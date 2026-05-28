package app

import (
	"fmt"
	"strings"

	formatpkg "github.com/watany-dev/gokui/internal/cli/format"
)

func argsRequestFormat(args []string, format formatpkg.Format) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) && args[i+1] == format.String() {
			return true
		}
		if strings.HasPrefix(args[i], "--format=") && strings.TrimPrefix(args[i], "--format=") == format.String() {
			return true
		}
	}
	return false
}

func requestedStructuredFormat(args []string, allowReviewJSON bool) (formatpkg.Format, bool) {
	if argsRequestFormat(args, formatpkg.JSON) {
		return formatpkg.JSON, true
	}
	if argsRequestFormat(args, formatpkg.SARIF) {
		return formatpkg.SARIF, true
	}
	if allowReviewJSON && argsRequestFormat(args, formatpkg.ReviewJSON) {
		return formatpkg.ReviewJSON, true
	}
	return "", false
}

func supportsCommandFormat(format string) bool {
	return formatpkg.SupportsCommand(format)
}

func supportsReviewCommandFormat(format string) bool {
	return formatpkg.SupportsReviewCommand(format)
}

func defaultCommandFormat() string {
	return formatpkg.Human.String()
}

type valueFlagHandler struct {
	flag string
	set  func(string)
}

type boolFlagHandler struct {
	flag string
	set  func()
}

type positionalArgHandler func(string) error

type commandArgParser struct {
	valueHandlers    []valueFlagHandler
	boolHandlers     []boolFlagHandler
	handlePositional positionalArgHandler
}

func formatValueFlag(format *string) valueFlagHandler {
	return valueFlagHandler{flag: "--format", set: func(value string) { *format = value }}
}

func targetValueFlag(target *string) valueFlagHandler {
	return valueFlagHandler{flag: "--target", set: func(value string) { *target = value }}
}

func profileValueFlag(profile *string, profileSet *bool) valueFlagHandler {
	return valueFlagHandler{flag: "--profile", set: func(value string) {
		*profile = value
		*profileSet = true
	}}
}

func singleSourcePositional(source *string, command string) positionalArgHandler {
	return func(arg string) error { return parseSingleSourcePositionalArg(source, command, arg) }
}

func optionalPathPositional(path *string, defaultPath string, command string) positionalArgHandler {
	return func(arg string) error {
		return parseOptionalPathPositionalArg(path, defaultPath, command, arg)
	}
}

func noPositional(command string) positionalArgHandler {
	return func(arg string) error { return parseNoPositionalArg(command, arg) }
}

func (p commandArgParser) parse(args []string, index int) (nextIndex int, err error) {
	return parseCommandArg(args, index, p.valueHandlers, p.boolHandlers, p.handlePositional)
}

func parseCommandArg(
	args []string,
	index int,
	valueHandlers []valueFlagHandler,
	boolHandlers []boolFlagHandler,
	handlePositional positionalArgHandler,
) (nextIndex int, err error) {
	arg := args[index]
	if next, ok, err := parseValueFlagHandlers(args, index, valueHandlers...); ok {
		return next, err
	}
	if parseBoolFlagHandlers(arg, boolHandlers...) {
		return index, nil
	}
	return index, handlePositional(arg)
}

func parseValueFlagHandlers(args []string, index int, handlers ...valueFlagHandler) (nextIndex int, ok bool, err error) {
	for _, handler := range handlers {
		value, next, matched, parseErr := parseValueFlagArg(args, index, handler.flag)
		if !matched {
			continue
		}
		if parseErr != nil {
			return index, true, parseErr
		}
		handler.set(value)
		return next, true, nil
	}
	return index, false, nil
}

func parseBoolFlagHandlers(arg string, handlers ...boolFlagHandler) bool {
	for _, handler := range handlers {
		if arg != handler.flag {
			continue
		}
		handler.set()
		return true
	}
	return false
}

func parseValueFlagArg(args []string, index int, flag string) (value string, nextIndex int, ok bool, err error) {
	arg := args[index]
	if arg == flag {
		if index+1 >= len(args) {
			return "", index, true, fmt.Errorf("missing value for %s", flag)
		}
		return args[index+1], index + 1, true, nil
	}
	if value, found := strings.CutPrefix(arg, flag+"="); found {
		return value, index, true, nil
	}
	return "", index, false, nil
}

func unknownOptionError(command string, arg string) error {
	return fmt.Errorf("unknown %s option: %s", command, arg)
}

func parseSingleSourcePositionalArg(source *string, command string, arg string) error {
	if strings.HasPrefix(arg, "-") {
		return unknownOptionError(command, arg)
	}
	return setSingleSourceArg(source, command, arg)
}

func setSingleSourceArg(source *string, command string, arg string) error {
	if *source != "" {
		return fmt.Errorf("%s accepts exactly one source", command)
	}
	*source = arg
	return nil
}

func parseOptionalPathPositionalArg(path *string, defaultPath string, command string, arg string) error {
	if strings.HasPrefix(arg, "-") {
		return unknownOptionError(command, arg)
	}
	return setOptionalPathArg(path, defaultPath, command, arg)
}

func setOptionalPathArg(path *string, defaultPath string, command string, arg string) error {
	if *path != defaultPath {
		return fmt.Errorf("%s accepts at most one path", command)
	}
	*path = arg
	return nil
}

func parseNoPositionalArg(command string, arg string) error {
	if strings.HasPrefix(arg, "-") {
		return unknownOptionError(command, arg)
	}
	return positionalArgNotAcceptedError(command, arg)
}

func positionalArgNotAcceptedError(command string, arg string) error {
	return fmt.Errorf("%s does not accept positional arguments: %s", command, arg)
}

func firstPositionalArg(args []string, valueFlags ...string) string {
	skipValue := make(map[string]struct{}, len(valueFlags))
	for _, flag := range valueFlags {
		skipValue[flag] = struct{}{}
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if _, ok := skipValue[arg]; ok {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--") {
			if flag, _, ok := strings.Cut(arg, "="); ok {
				if _, skip := skipValue[flag]; skip {
					continue
				}
			}
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

func flagValueArg(args []string, flag string, fallback string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == flag && i+1 < len(args) {
			return args[i+1]
		}
		if value, ok := strings.CutPrefix(args[i], flag+"="); ok {
			return value
		}
	}
	return fallback
}
