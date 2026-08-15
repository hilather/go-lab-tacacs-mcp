package operations

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func handleStatus(live StatusProvider) handleFunc {
	return func(_ context.Context, snap *state.Snapshot, _ Input) (any, error) {
		if snap == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
		}
		settings := snap.Settings()
		instanceID := ""
		listeners := make([]ListenerStatus, 0, 5)
		colocated := false
		if settings != nil {
			instanceID = settings.Server.InstanceID
			listeners = snapshotListeners(settings)
			colocated = settings.Listeners.LegacyTACACS.Enabled && settings.Listeners.SecureTACACS.Enabled
		}
		listeners = mergeLiveListeners(listeners, live)
		warning := ""
		if colocated {
			warning = ColocatedTopologyWarning
		}
		return Status{
			InstanceID:        instanceID,
			Revision:          snap.Revision,
			BaselineHash:      snap.BaselineHash,
			OverlayHash:       snap.OverlayHash,
			CompiledAt:        snap.CompiledAt,
			Listeners:         listeners,
			ColocatedTopology: colocated,
			TopologyWarning:   warning,
			Users:             len(snap.Users()),
			Groups:            len(snap.Groups()),
			Clients:           len(snap.Clients()),
			Tokens:            len(snap.Tokens()),
			Warnings:          snap.Warnings(),
		}, nil
	}
}

func snapshotListeners(settings *config.Document) []ListenerStatus {
	legacy := settings.Listeners.LegacyTACACS
	secure := settings.Listeners.SecureTACACS
	httpL := settings.Listeners.HTTP
	out := []ListenerStatus{
		{
			ID:             ListenerLegacy,
			Enabled:        legacy.Enabled,
			Bind:           legacy.Bind,
			AdvertisedPort: legacy.AdvertisedPort,
			Transport:      string(domain.TransportLegacy),
			Protocol:       string(domain.ProtocolTACACS),
			Carrier:        string(domain.CarrierTACACSLegacyTCP),
			Roles:          []string{string(domain.RoleAAA)},
		},
		{
			ID:             ListenerSecure,
			Enabled:        secure.Enabled,
			Bind:           secure.Bind,
			AdvertisedPort: secure.AdvertisedPort,
			Transport:      string(domain.TransportTLS),
			Protocol:       string(domain.ProtocolTACACS),
			Carrier:        string(domain.CarrierTACACSTLS),
			Roles:          []string{string(domain.RoleAAA)},
		},
		{
			ID:        ListenerHTTP,
			Enabled:   httpL.Enabled,
			Bind:      httpL.Bind,
			Transport: TransportHTTP,
			Protocol:  string(domain.ProtocolHTTP),
			Carrier:   string(domain.CarrierHTTPTCP),
			Roles:     []string{string(domain.RoleAdmin)},
		},
	}
	if settings.Listeners.RADIUSAccess.Enabled {
		out = append(out, radiusSnapshotStatus(settings.Listeners.RADIUSAccess, ListenerRADIUSAccess, domain.RoleAccess))
	}
	if settings.Listeners.RADIUSAccounting.Enabled {
		out = append(out, radiusSnapshotStatus(settings.Listeners.RADIUSAccounting, ListenerRADIUSAccounting, domain.RoleAccounting))
	}
	return out
}

func radiusSnapshotStatus(l config.RADIUSListener, id string, role domain.ListenerRole) ListenerStatus {
	return ListenerStatus{
		ID:        id,
		Enabled:   l.Enabled,
		Bind:      l.Bind,
		Transport: TransportUDP,
		Protocol:  string(domain.ProtocolRADIUS),
		Carrier:   string(domain.CarrierRADIUSUDP),
		Roles:     []string{string(role)},
		Required:  l.Required,
	}
}

// mergeLiveListeners overlays Runtime stats onto snapshot rows and appends
// inventory entries that are not already listed (RADIUS when registered).
func mergeLiveListeners(base []ListenerStatus, live StatusProvider) []ListenerStatus {
	if live == nil {
		return base
	}
	byID := make(map[string]int, len(base)+2)
	for i, row := range base {
		byID[row.ID] = i
	}
	for _, st := range live.Statuses() {
		got := listenerFromRuntime(st)
		if i, ok := byID[got.ID]; ok {
			base[i] = overlayLive(base[i], got)
			continue
		}
		base = append(base, got)
		byID[got.ID] = len(base) - 1
	}
	return base
}

func overlayLive(base, live ListenerStatus) ListenerStatus {
	base.Ready = live.Ready
	base.Inflight = live.Inflight
	base.QueueDepth = live.QueueDepth
	base.LastErrorCode = live.LastErrorCode
	base.Required = live.Required
	if base.Protocol == "" {
		base.Protocol = live.Protocol
	}
	if base.Carrier == "" {
		base.Carrier = live.Carrier
	}
	if len(base.Roles) == 0 {
		base.Roles = append([]string(nil), live.Roles...)
	}
	return base
}

func listenerFromRuntime(st runtime.Status) ListenerStatus {
	roles := make([]string, len(st.Roles))
	for i, role := range st.Roles {
		roles[i] = string(role)
	}
	return ListenerStatus{
		ID:            st.ID,
		Enabled:       st.Enabled,
		Bind:          st.Bind,
		Transport:     transportForRuntime(st),
		Protocol:      string(st.Protocol),
		Carrier:       string(st.Carrier),
		Roles:         roles,
		Ready:         st.Ready,
		Required:      st.Required,
		Inflight:      st.Inflight,
		QueueDepth:    st.QueueDepth,
		LastErrorCode: st.LastErrorCode,
	}
}

func transportForRuntime(st runtime.Status) string {
	switch st.Protocol {
	case domain.ProtocolTACACS:
		if st.Carrier == domain.CarrierTACACSTLS {
			return string(domain.TransportTLS)
		}
		return string(domain.TransportLegacy)
	case domain.ProtocolRADIUS:
		return TransportUDP
	default:
		return TransportHTTP
	}
}
