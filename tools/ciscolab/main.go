// Command ciscolab runs the optional Containerlab + Cisco IOL integration lab.
// Without TACLAB_IOL_IMAGE (or without a local image / containerlab) it skips
// with an explicit equipment-gap message and exit 0. Skip is not Cisco PASS.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	os.Exit(runMain(os.Args[1:]))
}

func runMain(args []string) int {
	fs := flag.NewFlagSet("ciscolab", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	checkTree := fs.Bool("check-tree", false, "only scan the repo for forbidden Cisco artifacts")
	generateOnly := fs.Bool("generate-only", false, "write topology and IOL partial into -dir and exit")
	dir := fs.String("dir", "", "workdir for generated files / deploy")
	evidence := fs.String("evidence", "", "evidence JSON path (default dist/cisco-lab-evidence.json)")
	skipDeploy := fs.Bool("skip-deploy", false, "detect only; do not deploy even if ready")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ciscolab: %v\n", err)
		return 2
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		if found, ferr := findModuleRoot(root); ferr == nil {
			root = found
		}
	}

	if *checkTree {
		hits, err := ForbiddenArtifacts(root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ciscolab: %v\n", err)
			return 1
		}
		if len(hits) > 0 {
			fmt.Fprintf(os.Stderr, "ciscolab: forbidden artifacts:\n")
			for _, h := range hits {
				fmt.Fprintf(os.Stderr, "  %s\n", h)
			}
			return 1
		}
		fmt.Println("cisco-lab: tree has no IOL binaries, refplat ISOs, or cisco_iol image tarballs")
		return 0
	}

	if *generateOnly {
		dest := *dir
		if dest == "" {
			dest = filepath.Join(root, "dist", "cisco-lab")
		}
		p := DefaultRenderParams(os.Getenv)
		p.SharedSecret = "TEST-ONLY-not-a-real-secret"
		if _, err := WriteGenerated(root, dest, p); err != nil {
			fmt.Fprintf(os.Stderr, "ciscolab: %v\n", err)
			return 1
		}
		fmt.Printf("cisco-lab: wrote %s\n", dest)
		return 0
	}

	_, code := Run(RunOptions{
		RepoRoot:     root,
		WorkDir:      *dir,
		EvidencePath: *evidence,
		SkipDeploy:   *skipDeploy,
	})
	return code
}

func findModuleRoot(start string) (string, error) {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}
