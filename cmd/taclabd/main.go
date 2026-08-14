// Command taclabd is the TacLab all-in-one TACACS+ / MCP lab appliance.
package main

import (
	"context"
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
	uiVersion = "0.0.0"
)

const usage = `taclabd — TacLab lab appliance

Usage:
  taclabd serve --config PATH
  taclabd validate --config PATH
  taclabd print-effective --config PATH [--redacted]
  taclabd healthcheck --url URL
  taclabd version
  taclabd -h | --help

serve binds the enabled TACACS listeners (legacy TCP and/or TLS 1.3),
enabled RADIUS/UDP listeners (stub path; default off), and the HTTP
admin listener (UI + REST + MCP). Reload is SIGHUP or config.reload.
File-watch reload is off.
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
	case "serve":
		if isHelp(args[1:]) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		return serve(context.Background(), args[1:], stdout, stderr)
	case "healthcheck":
		if isHelp(args[1:]) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		return healthcheck(args[1:], stdout, stderr)
	case "validate":
		if isHelp(args[1:]) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		return validateCmd(args[1:], stdout, stderr)
	case "print-effective":
		if isHelp(args[1:]) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		fmt.Fprintf(stderr, "taclabd print-effective: not implemented in this repository skeleton\n")
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
	fmt.Fprintf(w, "taclabd %s commit=%s built=%s ui=%s go=%s\n", version, commit, buildTime, uiVersion, runtime.Version())
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
