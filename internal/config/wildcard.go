package config

import (
	"fmt"
	"strings"
)

// ValidateWildcardServerName enforces RFC 9525-style wildcard limits and
// the TacLab TACACS-only subdomain rule. Non-wildcard names are accepted.
func ValidateWildcardServerName(name string) error {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return fmt.Errorf("server name is empty")
	}
	if !strings.Contains(name, "*") {
		return nil
	}
	labels := strings.Split(name, ".")
	if len(labels) < 4 {
		return fmt.Errorf("wildcard server identity must be a TACACS-only subdomain such as *.tacacs.lab.example")
	}
	if labels[0] != "*" {
		return fmt.Errorf("wildcard must be the entire leftmost label")
	}
	for i := 1; i < len(labels); i++ {
		if labels[i] == "" || strings.Contains(labels[i], "*") {
			return fmt.Errorf("wildcard is allowed only as the leftmost label")
		}
	}
	if labels[1] != "tacacs" {
		return fmt.Errorf("wildcard server identities must be limited to a tacacs subdomain (*.tacacs.…)")
	}
	return nil
}
