package main

import (
	"fmt"
	"io"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
)

func validateCmd(args []string, stdout, stderr io.Writer) int {
	path, err := parseConfigFlag(args)
	if err != nil {
		fmt.Fprintf(stderr, "taclabd validate: %v\n", err)
		return 2
	}
	doc, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "taclabd validate: %v\n", err)
		return 1
	}
	if err := config.Validate(doc); err != nil {
		fmt.Fprintf(stderr, "taclabd validate: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "ok")
	return 0
}
