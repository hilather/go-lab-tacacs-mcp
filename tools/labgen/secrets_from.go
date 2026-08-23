package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"gopkg.in/yaml.v3"
)

// labgenSharedSecretPolicy matches the policy rendered into generated YAML.
var labgenSharedSecretPolicy = config.SharedSecretPolicy{
	MinimumLengthCharacters: 16,
	MinimumCharacterClasses: 3,
	RejectKnownWeakValues:   true,
}

// secretsFromFile is the -secrets-from YAML. Every field is required.
// Unknown keys fail closed. Values are never logged.
type secretsFromFile struct {
	APIAdminToken           string `yaml:"api_admin_token"`
	LabSwitchesTacacsSecret string `yaml:"lab_switches_tacacs_secret"`
	LabSwitchesRadiusSecret string `yaml:"lab_switches_radius_secret"`
	Passwords               struct {
		LabAdmin          string `yaml:"lab-admin"`
		LabAdminEnable    string `yaml:"lab-admin-enable"`
		LabReadonly       string `yaml:"lab-readonly"`
		LabDisabled       string `yaml:"lab-disabled"`
		LabAdminChallenge string `yaml:"lab-admin-challenge"`
	} `yaml:"passwords"`
}

type labPlainSecrets struct {
	Token         string
	TacacsSecret  []byte
	RadiusSecret  []byte
	AdminPW       string
	EnablePW      string
	ReadonlyPW    string
	DisabledPW    string
	Challenge     string
	TokenEncoding string
}

func loadSecretsFrom(path string) (labPlainSecrets, error) {
	f, err := os.Open(path)
	if err != nil {
		return labPlainSecrets{}, fmt.Errorf("secrets-from: %w", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var raw secretsFromFile
	if err := dec.Decode(&raw); err != nil {
		return labPlainSecrets{}, fmt.Errorf("secrets-from: %w", err)
	}
	return validateSecretsFrom(raw)
}

func validateSecretsFrom(raw secretsFromFile) (labPlainSecrets, error) {
	token, err := requiredSecret("api_admin_token", raw.APIAdminToken)
	if err != nil {
		return labPlainSecrets{}, err
	}
	tacacs, err := requiredSecret("lab_switches_tacacs_secret", raw.LabSwitchesTacacsSecret)
	if err != nil {
		return labPlainSecrets{}, err
	}
	radius, err := requiredSecret("lab_switches_radius_secret", raw.LabSwitchesRadiusSecret)
	if err != nil {
		return labPlainSecrets{}, err
	}
	admin, err := requiredSecret("passwords.lab-admin", raw.Passwords.LabAdmin)
	if err != nil {
		return labPlainSecrets{}, err
	}
	enable, err := requiredSecret("passwords.lab-admin-enable", raw.Passwords.LabAdminEnable)
	if err != nil {
		return labPlainSecrets{}, err
	}
	ro, err := requiredSecret("passwords.lab-readonly", raw.Passwords.LabReadonly)
	if err != nil {
		return labPlainSecrets{}, err
	}
	dis, err := requiredSecret("passwords.lab-disabled", raw.Passwords.LabDisabled)
	if err != nil {
		return labPlainSecrets{}, err
	}
	chal, err := requiredSecret("passwords.lab-admin-challenge", raw.Passwords.LabAdminChallenge)
	if err != nil {
		return labPlainSecrets{}, err
	}

	if err := config.CheckSharedSecret(labgenSharedSecretPolicy, credentials.NewSharedSecret([]byte(tacacs)), "lab_switches_tacacs_secret"); err != nil {
		return labPlainSecrets{}, fmt.Errorf("secrets-from: lab_switches_tacacs_secret: %w", err)
	}
	if err := config.CheckRADIUSSharedSecret(labgenSharedSecretPolicy, credentials.NewRADIUSSharedSecret([]byte(radius)), "lab_switches_radius_secret"); err != nil {
		return labPlainSecrets{}, fmt.Errorf("secrets-from: lab_switches_radius_secret: %w", err)
	}
	if tacacs == radius {
		return labPlainSecrets{}, fmt.Errorf("secrets-from: TACACS and RADIUS shared secrets must be distinct")
	}

	return labPlainSecrets{
		Token:         token,
		TacacsSecret:  []byte(tacacs),
		RadiusSecret:  []byte(radius),
		AdminPW:       admin,
		EnablePW:      enable,
		ReadonlyPW:    ro,
		DisabledPW:    dis,
		Challenge:     chal,
		TokenEncoding: "caller-supplied",
	}, nil
}

func requiredSecret(field, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("secrets-from: %s is required", field)
	}
	if value != strings.TrimSpace(value) {
		return "", fmt.Errorf("secrets-from: %s has leading or trailing whitespace", field)
	}
	if strings.ContainsAny(value, "\n\r\x00") {
		return "", fmt.Errorf("secrets-from: %s contains a newline or NUL", field)
	}
	return value, nil
}
