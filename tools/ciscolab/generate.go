package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultTacLabIPv4   = "172.20.20.10"
	defaultIOLIPv4      = "172.20.20.11"
	defaultMgmtSubnet   = "172.20.20.0/24"
	defaultTacacsPort   = 4949
	defaultHTTPHostPort = 18080
	defaultTacLabImage  = "ghcr.io/hilather/go-lab-tacacs-mcp:dev"
)

// GeneratedLab is the workdir written by WriteGenerated.
type GeneratedLab struct {
	WorkDir     string
	Topology    string
	IOLPartial  string
	TopoPath    string
	PartialPath string
}

// DefaultRenderParams fills operator/env defaults. Image may be empty for generate-only tests.
func DefaultRenderParams(getenv func(string) string) RenderParams {
	if getenv == nil {
		getenv = os.Getenv
	}
	httpPort := defaultHTTPHostPort
	if v := strings.TrimSpace(getenv(EnvHTTPPort)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			httpPort = n
		}
	}
	tac := strings.TrimSpace(getenv(EnvTacLabImage))
	if tac == "" {
		tac = defaultTacLabImage
	}
	iol := strings.TrimSpace(getenv(EnvIOLImage))
	if iol == "" {
		iol = DefaultIOLImage
	}
	p := RenderParams{
		IOLImage:     iol,
		TacLabImage:  tac,
		TacLabIPv4:   firstNonEmpty(getenv(EnvTacLabIPv4), defaultTacLabIPv4),
		IOLIPv4:      firstNonEmpty(getenv(EnvIOLIPv4), defaultIOLIPv4),
		MgmtSubnet:   firstNonEmpty(getenv(EnvMgmtSubnet), defaultMgmtSubnet),
		TacacsPort:   defaultTacacsPort,
		HTTPHostPort: httpPort,
	}
	return p
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// WriteGenerated renders topology + IOL partial into dest.
func WriteGenerated(repoRoot, dest string, p RenderParams) (*GeneratedLab, error) {
	if dest == "" {
		return nil, fmt.Errorf("destination is required")
	}
	abs, err := filepath.Abs(dest)
	if err != nil {
		return nil, err
	}
	if p.LabDir == "" {
		p.LabDir = filepath.Join(abs, "lab")
	}
	p.LabDir, err = filepath.Abs(p.LabDir)
	if err != nil {
		return nil, err
	}
	topo, err := RenderTopology(repoRoot, p)
	if err != nil {
		return nil, err
	}
	if err := assertContainerlabIOL(topo); err != nil {
		return nil, err
	}
	partial, err := RenderIOLPartial(repoRoot, p)
	if err != nil {
		return nil, err
	}
	if err := assertIOLPointsAtTacLab(partial, p); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	topoPath := filepath.Join(abs, "topo.clab.yaml")
	partPath := filepath.Join(abs, "iol-aaa.cfg.partial")
	if err := os.WriteFile(topoPath, []byte(topo), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(partPath, []byte(partial), 0o600); err != nil {
		return nil, err
	}
	return &GeneratedLab{
		WorkDir:     abs,
		Topology:    topo,
		IOLPartial:  partial,
		TopoPath:    topoPath,
		PartialPath: partPath,
	}, nil
}

func assertContainerlabIOL(topo string) error {
	if !strings.Contains(topo, "kind: cisco_iol") {
		return fmt.Errorf("topology missing cisco_iol kind")
	}
	low := strings.ToLower(topo)
	for _, bad := range []string{"kind: gns3", "kind: dynamips", "kind: iou", "kind: cisco_iou", "kind: vr-iou"} {
		if strings.Contains(low, bad) {
			return fmt.Errorf("topology must not use %s", bad)
		}
	}
	if !strings.Contains(topo, "kind: linux") || !strings.Contains(low, "taclab") {
		return fmt.Errorf("topology missing TacLab linux node")
	}
	return nil
}

func assertIOLPointsAtTacLab(partial string, p RenderParams) error {
	if !strings.Contains(partial, "tacacs server") {
		return fmt.Errorf("IOL config missing tacacs server")
	}
	if !strings.Contains(partial, p.TacLabIPv4) {
		return fmt.Errorf("IOL config missing TacLab address %s", p.TacLabIPv4)
	}
	port := strconv.Itoa(p.TacacsPort)
	if p.TacacsPort == 0 {
		port = strconv.Itoa(defaultTacacsPort)
	}
	if !strings.Contains(partial, port) {
		return fmt.Errorf("IOL config missing TACACS port %s", port)
	}
	return nil
}
