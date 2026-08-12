// Command taclabd is the TacLab all-in-one TACACS+ / MCP lab appliance.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// Build metadata; overridden via -ldflags at release build time.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

const usage = `taclabd — TacLab lab appliance

Usage:
  taclabd serve --config PATH
  taclabd validate --config PATH
  taclabd print-effective --config PATH [--redacted]
  taclabd healthcheck --url URL
  taclabd version
  taclabd -h | --help

Protocol listeners and admin surfaces are not implemented in this skeleton.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isHelp(args) {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if isVersion(args) {
		printVersion(stdout)
		return 0
	}

	cmd := args[0]
	switch cmd {
	case "serve", "validate", "print-effective", "healthcheck":
		if isHelp(args[1:]) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		fmt.Fprintf(stderr, "taclabd %s: not implemented in this repository skeleton\n", cmd)
		return 2
	default:
		if strings.HasPrefix(cmd, "-") {
			fmt.Fprintf(stderr, "unknown flag: %s\n\n", cmd)
		} else {
			fmt.Fprintf(stderr, "unknown command: %s\n\n", cmd)
		}
		fmt.Fprint(stderr, usage)
		return 2
	}
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "taclabd %s commit=%s built=%s go=%s\n", version, commit, buildTime, runtime.Version())
}

func isHelp(args []string) bool {
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			return true
		case "--":
			return false
		}
	}
	return false
}

func isVersion(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "-version", "--version", "version":
		return true
	default:
		return false
	}
}
