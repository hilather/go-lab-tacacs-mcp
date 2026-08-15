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

func TestOverlayFlattenResynthesizesTACACSEndpoints(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	before, ok := m.Snapshot().Client("sw")
	if !ok {
		t.Fatal("missing sw")
	}
	if len(before.Client.Endpoints) != 1 || before.Client.Endpoints[0].ID != "tacacs-legacy" {
		t.Fatalf("baseline endpoints=%+v", before.Client.Endpoints)
	}
	if len(before.Client.Endpoints[0].TACACS.AllowedMethods) != 0 {
		t.Fatalf("baseline methods=%v", before.Client.Endpoints[0].TACACS.AllowedMethods)
	}

	rev := m.Revision()
	snap, err := m.UpdateClient("sw", UpdateClient{
		Authentication: &config.ClientAuth{AllowedMethods: []config.AuthMethod{config.AuthMethodASCII}},
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := snap.Client("sw")
	if len(got.Client.Endpoints) != 1 || got.Client.Endpoints[0].ID != "tacacs-legacy" {
		t.Fatalf("after auth endpoints=%+v", got.Client.Endpoints)
	}
	if len(got.Client.Endpoints[0].TACACS.AllowedMethods) != 1 || got.Client.Endpoints[0].TACACS.AllowedMethods[0] != config.AuthMethodASCII {
		t.Fatalf("endpoint methods=%v flatten=%v", got.Client.Endpoints[0].TACACS.AllowedMethods, got.Client.Authentication.AllowedMethods)
	}

	rev = snap.Revision
	snap, err = m.UpdateClient("sw", UpdateClient{
		Match: &config.ClientMatch{
			SourceCIDRs: []string{"10.20.0.0/16", "2001:db8:20::/48"},
			Transports:  []domain.Transport{domain.TransportTLS},
			Mode:        domain.MatchAddressAndCertificate,
		},
		SharedSecret: &SecretPatch{Clear: true},
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = snap.Client("sw")
	if len(got.Client.Endpoints) != 1 || got.Client.Endpoints[0].ID != "tacacs-tls" || got.Client.Endpoints[0].Transport != config.EndpointTransportTLS {
		t.Fatalf("tls switch endpoints=%+v", got.Client.Endpoints)
	}
	if got.Client.Endpoints[0].TACACS.SharedSecret.Set() {
		t.Fatal("tls endpoint kept legacy secret")
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
