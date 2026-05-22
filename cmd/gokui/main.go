package main

import (
	"io"
	"os"

	"github.com/watany-dev/gokui/internal/app"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	cfg := app.Config{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	return app.Run(args, stdout, stderr, cfg)
}
