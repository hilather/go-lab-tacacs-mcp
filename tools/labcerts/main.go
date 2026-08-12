// Command labcerts writes the reference TacLab PKI into a directory.
// Private keys are lab/test only and must not be committed.
package main

import (
	"fmt"
	"os"

	tacacstls "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/tls"
)

func main() {
	dir := "testdata/tls/lab"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	pki, err := tacacstls.GenerateLabPKI(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "labcerts: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote lab PKI under %s\n", pki.Dir)
	fmt.Printf("  server chain: %s\n", pki.ServerChain)
	fmt.Printf("  client CA:    %s\n", pki.ClientCACert)
	fmt.Printf("  client cert:  %s\n", pki.ClientOKCert)
	fmt.Printf("  crl (empty):  %s\n", pki.CRLEmpty)
}
