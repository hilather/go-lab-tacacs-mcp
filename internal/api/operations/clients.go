package operations

import (
	"context"
	"sort"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func handleClientsList(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	req, _ := in.Request.(ListClientsRequest)
	limit := normalizePage(req.Limit)
	live := snap.Clients()
	ids := make([]string, 0, len(live))
	byID := make(map[string]Client, len(live))
	for _, c := range live {
		ids = append(ids, c.Client.ID)
		byID[c.Client.ID] = clientView(c, snap.Revision)
	}
	if req.IncludeDeleted {
		for _, t := range tombstonesOf(snap, domain.KindClient) {
			id := string(t.ID)
			if _, ok := byID[id]; ok {
				continue
			}
			ids = append(ids, id)
			byID[id] = deletedClient(t, snap.Revision)
		}
		sort.Strings(ids)
	}
	start, end, next := pageAfter(ids, req.Cursor, limit)
	items := make([]Client, 0, end-start)
	for _, id := range ids[start:end] {
		items = append(items, byID[id])
	}
	return ClientList{Revision: snap.Revision, Items: items, NextCursor: next}, nil
}

func handleClientsGet(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	req, _ := in.Request.(GetClientRequest)
	if err := requireID(req.ID); err != nil {
		return nil, err
	}
	if c, ok := snap.Client(req.ID); ok {
		return clientView(c, snap.Revision), nil
	}
	if req.IncludeDeleted {
		if t, ok := findTombstone(snap, domain.KindClient, req.ID); ok {
			return deletedClient(t, snap.Revision), nil
		}
	}
	return nil, domain.NewError(domain.CodeNotFound, "client not found").WithPath("clients/" + req.ID)
}

func handleClientsCreate(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		if err := requireState(deps); err != nil {
			return nil, err
		}
		req, _ := in.Request.(CreateClientRequest)
		if err := requireID(req.ID); err != nil {
			return nil, err
		}
		match, err := clientMatchFromView(req.Match)
		if err != nil {
			return nil, err
		}
		authn, err := clientAuthFromView(req.Authentication)
		if err != nil {
			return nil, err
		}
		life, err := lifecycleFromView(req.SharedSecretLifecycle)
		if err != nil {
			return nil, err
		}
		published, err := deps.State.CreateClient(state.CreateClient{
			ID:                    req.ID,
			DisplayName:           req.DisplayName,
			Enabled:               req.Enabled,
			Priority:              req.Priority,
			Labels:                req.Labels,
			Match:                 match,
			SharedSecret:          req.SharedSecret.patch(),
			SharedSecretLifecycle: life,
			Authentication:        authn,
			Authorization:         clientAuthzFromView(req.Authorization),
			Accounting:            clientAcctFromView(req.Accounting),
			Override:              req.Override,
		}, in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		c, ok := published.Client(req.ID)
		if !ok {
			return nil, domain.NewError(domain.CodeInternal, "created client is missing from snapshot")
		}
		audit(deps, "api.client.created", "ok", published.Revision)
		return clientView(c, published.Revision), nil
	}
}

func handleClientsUpdate(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		if err := requireState(deps); err != nil {
			return nil, err
		}
		req, _ := in.Request.(UpdateClientRequest)
		if err := requireID(req.ID); err != nil {
			return nil, err
		}
		match, err := clientMatchFromView(req.Match)
		if err != nil {
			return nil, err
		}
		authn, err := clientAuthFromView(req.Authentication)
		if err != nil {
			return nil, err
		}
		life, err := lifecycleFromView(req.SharedSecretLifecycle)
		if err != nil {
			return nil, err
		}
		published, err := deps.State.UpdateClient(req.ID, state.UpdateClient{
			DisplayName:           req.DisplayName,
			Enabled:               req.Enabled,
			Priority:              req.Priority,
			Labels:                req.Labels,
			Match:                 match,
			SharedSecret:          req.SharedSecret.patch(),
			SharedSecretLifecycle: life,
			Authentication:        authn,
			Authorization:         clientAuthzFromView(req.Authorization),
			Accounting:            clientAcctFromView(req.Accounting),
		}, in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		c, ok := published.Client(req.ID)
		if !ok {
			return nil, domain.NewError(domain.CodeInternal, "updated client is missing from snapshot")
		}
		audit(deps, "api.client.updated", "ok", published.Revision)
		return clientView(c, published.Revision), nil
	}
}

func handleClientsDelete(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		if err := requireState(deps); err != nil {
			return nil, err
		}
		req, _ := in.Request.(DeleteClientRequest)
		if err := requireID(req.ID); err != nil {
			return nil, err
		}
		published, err := deps.State.DeleteClient(req.ID, state.DeleteOptions{
			Tombstone: req.Tombstone,
			ActorID:   in.Actor.ID,
		}, in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		audit(deps, "api.client.deleted", "ok", published.Revision)
		return DeleteResult{ID: req.ID, Revision: published.Revision}, nil
	}
}
