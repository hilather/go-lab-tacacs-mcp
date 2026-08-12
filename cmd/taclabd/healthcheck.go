package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func healthcheck(args []string, stdout, stderr io.Writer) int {
	url := "http://127.0.0.1:8080/health/ready"
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--url" || a == "-url":
			if i+1 >= len(args) {
				fmt.Fprintf(stderr, "taclabd healthcheck: --url requires a value\n")
				return 2
			}
			i++
			url = args[i]
		case strings.HasPrefix(a, "--url="):
			url = a[len("--url="):]
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "taclabd healthcheck: unknown flag: %s\n", a)
			return 2
		default:
			fmt.Fprintf(stderr, "taclabd healthcheck: unexpected argument: %s\n", a)
			return 2
		}
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(stderr, "taclabd healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "taclabd healthcheck: %s\n", resp.Status)
		return 1
	}
	fmt.Fprintln(stdout, "ok")
	return 0
}
