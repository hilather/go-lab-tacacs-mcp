// Command check-registries validates conformance and operation YAML registries.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hilather/go-lab-tacacs-mcp/tools/registry"
)

func main() {
	writeDocs := flag.Bool("write-docs", false, "write docs/generated inventories after a successful validation")
	flag.Parse()

	root, err := registry.FindRoot(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-registries: %v\n", err)
		os.Exit(2)
	}
	if !registry.RegistriesPresent(root) {
		fmt.Fprintf(os.Stderr, "check-registries: registry files missing under %s\n", root)
		os.Exit(2)
	}

	rep, err := registry.ValidateRoot(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-registries: %v\n", err)
		os.Exit(2)
	}
	if !rep.Valid() {
		for _, issue := range rep.Issues {
			fmt.Fprintln(os.Stderr, issue)
		}
		fmt.Fprintf(os.Stderr, "check-registries: %d issue(s)\n", len(rep.Issues))
		os.Exit(1)
	}

	if *writeDocs {
		if err := registry.GenerateDocs(root, rep.Operations, rep.RFC8907, rep.RFC9887); err != nil {
			fmt.Fprintf(os.Stderr, "check-registries: write docs: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("check-registries: ok (%d operations, %d RFC 8907 rows, %d RFC 9887 rows)\n",
		len(rep.Operations.Operations), len(rep.RFC8907.Rows), len(rep.RFC9887.Rows))
}
