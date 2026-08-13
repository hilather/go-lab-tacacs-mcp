package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	EnvIOLImage    = "TACLAB_IOL_IMAGE"
	EnvTacLabImage = "TACLAB_IMAGE"
	EnvTacLabIPv4  = "TACLAB_CISCO_TACLAB_IPV4"
	EnvIOLIPv4     = "TACLAB_CISCO_IOL_IPV4"
	EnvMgmtSubnet  = "TACLAB_CISCO_MGMT_SUBNET"
	EnvHTTPPort    = "TACLAB_CISCO_HTTP_PORT"
	EnvKeep        = "TACLAB_CISCO_KEEP"
	EnvEvidence    = "TACLAB_CISCO_EVIDENCE"

	StatusSkip  = "skip"
	StatusReady = "ready"

	SkipImageUnset     = "CISCO-LAB: SKIP — equipment gap: TACLAB_IOL_IMAGE is unset (no operator-supplied vrnetlab cisco_iol image)"
	SkipImageMissing   = "CISCO-LAB: SKIP — equipment gap: IOL image not present locally (will not pull or vendor Cisco software)"
	SkipNoContainerlab = "CISCO-LAB: SKIP — equipment gap: containerlab not on PATH"
	SkipNoDocker       = "CISCO-LAB: SKIP — equipment gap: docker is not available to inspect a local IOL image"
)

// DefaultIOLImage is documentation-only. Detect never pulls this tag.
const DefaultIOLImage = "vrnetlab/cisco_iol:17.12.01"

// Decision is the skip-or-ready result of Detect.
type Decision struct {
	Status            string `json:"status"`
	Reason            string `json:"reason"`
	IOLImage          string `json:"iol_image,omitempty"`
	Containerlab      string `json:"containerlab,omitempty"`
	WouldPull         bool   `json:"would_pull"`
	ConformanceClaim  string `json:"conformance_claim"`
	CiscoPass         bool   `json:"cisco_pass"`
	DeviceFamilyClaim bool   `json:"device_family_completeness"`
}

// Lookups are injectable for tests. Production uses OSLookups.
type Lookups struct {
	Getenv      func(string) string
	LookPath    func(string) (string, error)
	ImageExists func(name string) (bool, error)
}

// OSLookups talks to the real environment. ImageExists uses docker inspect only.
func OSLookups() Lookups {
	return Lookups{
		Getenv:   os.Getenv,
		LookPath: exec.LookPath,
		ImageExists: func(name string) (bool, error) {
			return dockerImageInspectOnly(name)
		},
	}
}

// Detect decides skip vs ready. It never pulls an image and never claims PASS.
func Detect(l Lookups) Decision {
	d := Decision{
		WouldPull:         false,
		ConformanceClaim:  "none",
		CiscoPass:         false,
		DeviceFamilyClaim: false,
	}
	if l.Getenv == nil {
		l.Getenv = os.Getenv
	}
	if l.LookPath == nil {
		l.LookPath = exec.LookPath
	}
	if l.ImageExists == nil {
		l.ImageExists = dockerImageInspectOnly
	}

	img := strings.TrimSpace(l.Getenv(EnvIOLImage))
	if img == "" {
		d.Status = StatusSkip
		d.Reason = SkipImageUnset
		return d
	}
	d.IOLImage = img

	if _, err := l.LookPath("docker"); err != nil {
		d.Status = StatusSkip
		d.Reason = SkipNoDocker
		return d
	}

	exists, err := l.ImageExists(img)
	if err != nil {
		d.Status = StatusSkip
		d.Reason = SkipImageMissing + ": " + err.Error()
		return d
	}
	if !exists {
		d.Status = StatusSkip
		d.Reason = SkipImageMissing
		return d
	}

	clab, err := findContainerlab(l.LookPath)
	if err != nil {
		d.Status = StatusSkip
		d.Reason = SkipNoContainerlab
		return d
	}
	d.Containerlab = clab
	d.Status = StatusReady
	d.Reason = "containerlab and local IOL image are present"
	return d
}

// ClaimCiscoPass is true only for a live successful Cisco interop run.
// Skip is never PASS.
func ClaimCiscoPass(d Decision) bool {
	return d.Status != StatusSkip && d.CiscoPass
}

func findContainerlab(lookPath func(string) (string, error)) (string, error) {
	for _, name := range []string{"containerlab", "clab"} {
		p, err := lookPath(name)
		if err == nil && p != "" {
			return p, nil
		}
	}
	return "", fmt.Errorf("not found")
}

// dockerImageInspectOnly must never invoke docker pull / docker image pull.
func dockerImageInspectOnly(name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	cmd := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", name)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.ToLower(stderr.String() + err.Error())
		if strings.Contains(msg, "no such image") || strings.Contains(msg, "not found") {
			return false, nil
		}
		return false, fmt.Errorf("docker image inspect: %w", err)
	}
	return strings.TrimSpace(string(out)) != "", nil
}
