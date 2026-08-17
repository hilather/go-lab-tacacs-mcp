package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

func (h *harness) labRADIUSDynAuth() error {
	return h.labOptionalRADIUSListener("radius_dynauth", "radius", "udp")
}

func (h *harness) labRADIUSRadSec() error {
	return h.labOptionalRADIUSListener("radius_radsec", "radius", "tls")
}

// labOptionalRADIUSListener returns errSkip when the listener is default-off.
func (h *harness) labOptionalRADIUSListener(id, protocol, transport string) error {
	listeners, raw, err := h.statusListeners()
	if err != nil {
		return err
	}
	return checkOptionalRADIUSListener(h.RadiusSecret, listeners, raw, id, protocol, transport)
}

func checkOptionalRADIUSListener(secret []byte, listeners map[string]statusListener, raw []byte, id, protocol, transport string) error {
	if err := rejectSecret(raw, secret); err != nil {
		return err
	}
	l, ok := listeners[id]
	if !ok || !l.Enabled {
		return fmt.Errorf("%w: %s (default off)", errSkip, id)
	}
	if !l.Ready {
		return fmt.Errorf("%s enabled but not ready: %+v", id, l)
	}
	if l.Protocol != protocol || l.Transport != transport {
		return fmt.Errorf("%s protocol=%s transport=%s want %s/%s", id, l.Protocol, l.Transport, protocol, transport)
	}
	return nil
}

func rejectSecret(raw, secret []byte) error {
	if len(secret) == 0 {
		return nil
	}
	if bytes.Contains(raw, secret) {
		return fmt.Errorf("RADIUS shared secret in status")
	}
	return nil
}

func (h *harness) labRADIUSReady() error {
	listeners, raw, err := h.statusListeners()
	if err != nil {
		return err
	}
	if err := h.rejectCanary(raw); err != nil {
		return err
	}
	access, ok := listeners["radius_access"]
	if !ok || !access.Enabled || !access.Ready {
		return fmt.Errorf("radius_access not ready: %+v", access)
	}
	if access.Protocol != "radius" || access.Transport != "udp" {
		return fmt.Errorf("radius_access protocol=%s transport=%s", access.Protocol, access.Transport)
	}
	acct, ok := listeners["radius_accounting"]
	if !ok || !acct.Enabled || !acct.Ready {
		return fmt.Errorf("radius_accounting not ready: %+v", acct)
	}
	if acct.Protocol != "radius" || acct.Transport != "udp" {
		return fmt.Errorf("radius_accounting protocol=%s transport=%s", acct.Protocol, acct.Transport)
	}
	if bytes.Contains(raw, h.RadiusSecret) {
		return fmt.Errorf("RADIUS shared secret in status")
	}
	return nil
}

func (h *harness) labRADIUSAccessTest() error {
	pass := h.pw("lab-admin")
	if pass == "" {
		return fmt.Errorf("lab-admin password required")
	}
	body := map[string]any{
		"client_id": "lab-switches",
		"user_id":   "lab-admin",
		"method":    map[string]any{"type": "pap", "password": pass},
		"explain":   true,
	}
	code, raw, err := h.restJSON(http.MethodPost, "/api/v1/radius/access:test", body, nil)
	if err != nil {
		return err
	}
	if err := statusOK(code, raw); err != nil {
		return err
	}
	if err := mustContain(raw, "access_accept"); err != nil {
		return err
	}
	if bytes.Contains(raw, []byte(pass)) {
		return fmt.Errorf("password leaked in radius.access.test")
	}
	if bytes.Contains(raw, h.RadiusSecret) {
		return fmt.Errorf("RADIUS secret leaked in radius.access.test")
	}

	bad := map[string]any{
		"client_id": "lab-switches",
		"user_id":   "lab-admin",
		"method":    map[string]any{"type": "pap", "password": "wrong-password-!!!!"},
	}
	code, raw, err = h.restJSON(http.MethodPost, "/api/v1/radius/access:test", bad, nil)
	if err != nil {
		return err
	}
	if err := statusOK(code, raw); err != nil {
		return err
	}
	if bytes.Contains(raw, []byte("access_accept")) {
		return fmt.Errorf("wrong password accepted")
	}
	if err := mustContain(raw, "access_reject"); err != nil {
		return err
	}
	return nil
}

func (h *harness) labRADIUSOnlyProfile() error {
	c, err := net.DialTimeout("tcp", h.Legacy, time.Second)
	if err == nil {
		_ = c.Close()
		return fmt.Errorf("legacy %s accepted on RADIUS-only profile", h.Legacy)
	}
	c, err = net.DialTimeout("tcp", h.TLS, time.Second)
	if err == nil {
		_ = c.Close()
		return fmt.Errorf("tls %s accepted on RADIUS-only profile", h.TLS)
	}
	listeners, raw, err := h.statusListeners()
	if err != nil {
		return err
	}
	if err := statusHasReadyRADIUS(listeners); err != nil {
		return err
	}
	if tacacsListenerReady(listeners, "legacy_tacacs") || tacacsListenerReady(listeners, "secure_tacacs") {
		return fmt.Errorf("TACACS listener still ready on RADIUS-only: %s", raw)
	}
	return nil
}

func (h *harness) labTACACSOnlyReady() error {
	listeners, _, err := h.statusListeners()
	if err != nil {
		return err
	}
	if radiusListenerReady(listeners, "radius_access") || radiusListenerReady(listeners, "radius_accounting") {
		return fmt.Errorf("RADIUS listener ready on TACACS-only profile")
	}
	legacy, legacyOK := listeners["legacy_tacacs"]
	secure, secureOK := listeners["secure_tacacs"]
	if (!legacyOK || !legacy.Enabled) && (!secureOK || !secure.Enabled) {
		return fmt.Errorf("no TACACS listener enabled")
	}
	return nil
}

type statusListener struct {
	ID        string `json:"id"`
	Enabled   bool   `json:"enabled"`
	Ready     bool   `json:"ready"`
	Protocol  string `json:"protocol"`
	Transport string `json:"transport"`
}

func (h *harness) statusListeners() (map[string]statusListener, []byte, error) {
	code, raw, err := h.restJSON(http.MethodGet, "/api/v1/status", nil, nil)
	if err != nil {
		return nil, raw, err
	}
	if err := statusOK(code, raw); err != nil {
		return nil, raw, err
	}
	out, err := parseStatusListeners(raw)
	return out, raw, err
}

func parseStatusListeners(raw []byte) (map[string]statusListener, error) {
	var env struct {
		Data struct {
			Listeners []statusListener `json:"listeners"`
		} `json:"data"`
		Listeners []statusListener `json:"listeners"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	items := env.Data.Listeners
	if len(items) == 0 {
		items = env.Listeners
	}
	out := make(map[string]statusListener, len(items))
	for _, it := range items {
		if it.ID != "" {
			out[it.ID] = it
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("status missing listeners")
	}
	return out, nil
}

func radiusListenerReady(m map[string]statusListener, id string) bool {
	l, ok := m[id]
	return ok && l.Enabled && l.Ready
}

func tacacsListenerReady(m map[string]statusListener, id string) bool {
	l, ok := m[id]
	return ok && l.Enabled && l.Ready
}

func statusHasReadyRADIUS(m map[string]statusListener) error {
	if !radiusListenerReady(m, "radius_access") {
		return fmt.Errorf("radius_access not ready")
	}
	if !radiusListenerReady(m, "radius_accounting") {
		return fmt.Errorf("radius_accounting not ready")
	}
	return nil
}
