package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

//go:embed templates/topo.clab.yaml.tmpl
var embeddedTopo string

//go:embed templates/iol-aaa.cfg.partial.tmpl
var embeddedIOLPartial string

// RenderParams fill the committed Containerlab + IOL templates.
type RenderParams struct {
	IOLImage     string
	TacLabImage  string
	TacLabIPv4   string
	IOLIPv4      string
	MgmtSubnet   string
	TacacsPort   int
	HTTPHostPort int
	LabDir       string
	SharedSecret string
}

// QuotedSecret is an IOS-safe quoted TACACS key (secrets may contain '#').
func (p RenderParams) QuotedSecret() string {
	return strconv.Quote(p.SharedSecret)
}

func loadTemplate(repoRoot, name, embedded string) (string, error) {
	if repoRoot != "" {
		p := filepath.Join(repoRoot, "deployments", "containerlab", name)
		b, err := os.ReadFile(p)
		if err == nil {
			return string(b), nil
		}
	}
	if embedded == "" {
		return "", fmt.Errorf("template %s not found", name)
	}
	return embedded, nil
}

// RenderTopology writes the Containerlab topology (cisco_iol + TacLab linux).
func RenderTopology(repoRoot string, p RenderParams) (string, error) {
	src, err := loadTemplate(repoRoot, "topo.clab.yaml.tmpl", embeddedTopo)
	if err != nil {
		return "", err
	}
	return execTemplate("topo", src, p)
}

// RenderIOLPartial writes the IOL AAA snippet that targets TacLab.
func RenderIOLPartial(repoRoot string, p RenderParams) (string, error) {
	src, err := loadTemplate(repoRoot, "iol-aaa.cfg.partial.tmpl", embeddedIOLPartial)
	if err != nil {
		return "", err
	}
	return execTemplate("iol", src, p)
}

func execTemplate(name, src string, p RenderParams) (string, error) {
	tmpl, err := template.New(name).Parse(src)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", err
	}
	out := buf.String()
	if strings.Contains(out, "{{") {
		return "", fmt.Errorf("%s: unexpanded template marker", name)
	}
	return out, nil
}
