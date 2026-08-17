package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderTopologyIsContainerlabIOLNotGNS3(t *testing.T) {
	p := RenderParams{
		IOLImage:     "vrnetlab/cisco_iol:17.12.01",
		TacLabImage:  "ghcr.io/hilather/go-lab-tacacs-mcp:dev",
		TacLabIPv4:   "172.20.20.10",
		IOLIPv4:      "172.20.20.11",
		MgmtSubnet:   "172.20.20.0/24",
		TacacsPort:   4949,
		HTTPHostPort: 18080,
		LabDir:       "/tmp/labdir",
		SharedSecret: "s3cret#value",
	}
	topo, err := RenderTopology(repoRoot(t), p)
	if err != nil {
		t.Fatal(err)
	}
	if err := assertContainerlabIOL(topo); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(topo, "kind: cisco_iol") {
		t.Fatal("missing cisco_iol")
	}
	if !strings.Contains(topo, "172.20.20.10") || !strings.Contains(topo, "taclab") {
		t.Fatal("TacLab node / address missing")
	}
	low := strings.ToLower(topo)
	for _, bad := range []string{"kind: gns3", "kind: dynamips", "kind: iou"} {
		if strings.Contains(low, bad) {
			t.Fatalf("forbidden integrator %s", bad)
		}
	}
	if strings.Contains(topo, "{{") {
		t.Fatal("unexpanded template")
	}

	partial, err := RenderIOLPartial(repoRoot(t), p)
	if err != nil {
		t.Fatal(err)
	}
	if err := assertIOLPointsAtTacLab(partial, p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(partial, "4949") {
		t.Fatal("legacy TACACS port 4949 missing")
	}
	if !strings.Contains(partial, `"s3cret#value"`) {
		t.Fatal("quoted shared secret missing (IOS # is a comment)")
	}

	radius, err := RenderIOLRADIUSPartial(repoRoot(t), p)
	if err != nil {
		t.Fatal(err)
	}
	if err := assertIOLRADIUSPointsAtTacLab(radius, p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(radius, "1812") || !strings.Contains(radius, "radius server") {
		t.Fatal("optional RADIUS IOL snippet missing")
	}
	if strings.Contains(strings.ToLower(radius), "pass") && !strings.Contains(radius, "not PRJ-CISCO-001 PASS") {
		t.Fatal("RADIUS snippet must not claim PASS")
	}
}

func TestWriteGeneratedUsesSecretFileNotHardcodedImageBytes(t *testing.T) {
	dir := t.TempDir()
	p := DefaultRenderParams(func(string) string { return "" })
	p.SharedSecret = "from-labgen-file-not-image-bytes"
	p.LabDir = filepath.Join(dir, "lab")
	got, err := WriteGenerated(repoRoot(t), dir, p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Topology, "cisco_iol") {
		t.Fatal(got.Topology)
	}
	raw, err := os.ReadFile(got.PartialPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), p.SharedSecret) {
		t.Fatal("generated partial should include substituted key")
	}
	rad, err := os.ReadFile(got.RADIUSPartialPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rad), "radius server") || !strings.Contains(string(rad), "not PRJ-CISCO-001 PASS") {
		t.Fatalf("optional RADIUS partial: %s", rad)
	}
}

func TestCommittedTemplatesHaveNoSecretMaterial(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{
		"deployments/containerlab/topo.clab.yaml.tmpl",
		"deployments/containerlab/iol-aaa.cfg.partial.tmpl",
		"tools/ciscolab/templates/topo.clab.yaml.tmpl",
		"tools/ciscolab/templates/iol-aaa.cfg.partial.tmpl",
	} {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		body := string(b)
		if strings.Contains(body, "from-labgen") || strings.Contains(body, "Adm") && strings.Contains(body, "password") {
			t.Fatalf("%s looks like it contains a filled secret", rel)
		}
		if rel == "deployments/containerlab/iol-aaa.cfg.partial.tmpl" && !strings.Contains(body, "{{.QuotedSecret}}") {
			t.Fatalf("%s must not bake a TACACS key", rel)
		}
	}
}

func TestEmbeddedTemplatesMatchDeployments(t *testing.T) {
	root := repoRoot(t)
	pairs := []struct{ rel, embed string }{
		{"deployments/containerlab/topo.clab.yaml.tmpl", embeddedTopo},
		{"deployments/containerlab/iol-aaa.cfg.partial.tmpl", embeddedIOLPartial},
	}
	for _, p := range pairs {
		b, err := os.ReadFile(filepath.Join(root, p.rel))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != p.embed {
			t.Fatalf("drift between %s and embed", p.rel)
		}
	}
}

func TestLabTestDoesNotRequireCiscoLab(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "tools", "lab-test.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "ciscolab") || strings.Contains(string(b), "cisco-lab") {
		t.Fatal("make lab-test / compose-lab must stay independent of the optional Cisco IOL path")
	}
}

func TestNoDockerPullInShippedSources(t *testing.T) {
	root := filepath.Join(repoRoot(t), "tools", "ciscolab")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(b)
		if strings.Contains(src, "exec.Command(\"docker\", \"pull\"") || strings.Contains(src, "exec.CommandContext(ctx, \"docker\", \"pull\"") {
			t.Errorf("%s must not pull Cisco images", path)
		}
		if strings.Contains(src, `"golang.org/x/crypto/ssh"`) {
			t.Errorf("%s must not import x/crypto/ssh (govulncheck GO-2026-5020)", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
