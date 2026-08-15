package state

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestOverlayRADIUSFlattenCreatesEndpoint(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	enabled := true
	snap, err := m.CreateClient(CreateClient{
		ID: "rad",
		Match: &config.ClientMatch{
			SourceCIDRs: []string{"10.9.0.0/16"},
			Transports:  []domain.Transport{domain.TransportLegacy},
			Mode:        domain.MatchAddressAndCertificate,
		},
		SharedSecret: &SecretPatch{Ref: config.SecretRef{File: "/run/secrets/rad-tacacs"}},
		RADIUS: &RADIUSPatch{
			Enabled:      &enabled,
			SharedSecret: &SecretPatch{Ref: config.SecretRef{File: "/run/secrets/rad-radius"}},
			Roles:        []domain.ListenerRole{domain.RoleAccess, domain.RoleAccounting},
		},
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := snap.Client("rad")
	if !ok {
		t.Fatal("missing rad")
	}
	if radiusSecretFile(got.Client) != "/run/secrets/rad-radius" {
		t.Fatalf("radius secret=%q", radiusSecretFile(got.Client))
	}
	if got.Client.Legacy.SharedSecret.File != "/run/secrets/rad-tacacs" {
		t.Fatalf("tacacs secret=%+v", got.Client.Legacy.SharedSecret)
	}
}

func TestOverlayEndpointsDisagreeWithFlatten(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSYAML)
	rev := m.Revision()
	_, err := m.UpdateClient("lab-switches", UpdateClient{
		Authentication: &config.ClientAuth{AllowedMethods: []config.AuthMethod{config.AuthMethodASCII}},
		Endpoints: &[]config.ClientEndpoint{{
			ID:        "tacacs-legacy",
			Protocol:  domain.ProtocolTACACS,
			Transport: config.EndpointTransportTCP,
			Roles:     []domain.ListenerRole{domain.RoleAuthentication, domain.RoleAuthorization, domain.RoleAccounting},
			TACACS:    &config.TACACSEndpoint{AllowedMethods: []config.AuthMethod{config.AuthMethodPAP}},
		}},
	}, &rev)
	if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeInvalidArgument {
		t.Fatalf("got %v", err)
	}
}
