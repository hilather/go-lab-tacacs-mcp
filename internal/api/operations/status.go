package operations

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func handleStatus(_ context.Context, snap *state.Snapshot, _ Input) (any, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	settings := snap.Settings()
	instanceID := ""
	listeners := make([]ListenerStatus, 0, 3)
	colocated := false
	if settings != nil {
		instanceID = settings.Server.InstanceID
		legacy := settings.Listeners.LegacyTACACS
		secure := settings.Listeners.SecureTACACS
		httpL := settings.Listeners.HTTP
		listeners = append(listeners,
			ListenerStatus{
				ID:             ListenerLegacy,
				Enabled:        legacy.Enabled,
				Bind:           legacy.Bind,
				AdvertisedPort: legacy.AdvertisedPort,
				Transport:      string(domain.TransportLegacy),
			},
			ListenerStatus{
				ID:             ListenerSecure,
				Enabled:        secure.Enabled,
				Bind:           secure.Bind,
				AdvertisedPort: secure.AdvertisedPort,
				Transport:      string(domain.TransportTLS),
			},
			ListenerStatus{
				ID:        ListenerHTTP,
				Enabled:   httpL.Enabled,
				Bind:      httpL.Bind,
				Transport: TransportHTTP,
			},
		)
		colocated = legacy.Enabled && secure.Enabled
	}
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
