package operations

import (
	"context"
	"sort"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func handleGroupsList(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	req, _ := in.Request.(ListGroupsRequest)
	limit := normalizePage(req.Limit)
	live := snap.Groups()
	ids := make([]string, 0, len(live))
	byID := make(map[string]Group, len(live))
	for _, g := range live {
		ids = append(ids, g.Group.ID)
		byID[g.Group.ID] = groupView(g, snap.Revision)
	}
	if req.IncludeDeleted {
		for _, t := range tombstonesOf(snap, domain.KindGroup) {
			id := string(t.ID)
			if _, ok := byID[id]; ok {
				continue
			}
			ids = append(ids, id)
			byID[id] = deletedGroup(t, snap.Revision)
		}
		sort.Strings(ids)
	}
	start, end, next := pageAfter(ids, req.Cursor, limit)
	items := make([]Group, 0, end-start)
	for _, id := range ids[start:end] {
		items = append(items, byID[id])
	}
	return GroupList{Revision: snap.Revision, Items: items, NextCursor: next}, nil
}

func handleGroupsGet(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	req, _ := in.Request.(GetGroupRequest)
	if err := requireID(req.ID); err != nil {
		return nil, err
	}
	if g, ok := snap.Group(req.ID); ok {
		return groupView(g, snap.Revision), nil
	}
	if req.IncludeDeleted {
		if t, ok := findTombstone(snap, domain.KindGroup, req.ID); ok {
			return deletedGroup(t, snap.Revision), nil
		}
	}
	return nil, domain.NewError(domain.CodeNotFound, "group not found").WithPath("groups/" + req.ID)
}

func handleGroupsCreate(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		if err := requireState(deps); err != nil {
			return nil, err
		}
		req, _ := in.Request.(CreateGroupRequest)
		if err := requireID(req.ID); err != nil {
			return nil, err
		}
		svcs, cmds, action, err := groupRulePatches(req.Services, req.CommandRules, req.DefaultCommandAction)
		if err != nil {
			return nil, err
		}
		published, err := deps.State.CreateGroup(state.CreateGroup{
			ID:                   req.ID,
			DisplayName:          req.DisplayName,
			Enabled:              req.Enabled,
			Priority:             req.Priority,
			Labels:               req.Labels,
			Services:             svcs,
			CommandRules:         cmds,
			DefaultCommandAction: action,
			Override:             req.Override,
		}, in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		g, ok := published.Group(req.ID)
		if !ok {
			return nil, domain.NewError(domain.CodeInternal, "created group is missing from snapshot")
		}
		audit(deps, "api.group.created", "ok", published.Revision)
		return groupView(g, published.Revision), nil
	}
}

func handleGroupsUpdate(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		if err := requireState(deps); err != nil {
			return nil, err
		}
		req, _ := in.Request.(UpdateGroupRequest)
		if err := requireID(req.ID); err != nil {
			return nil, err
		}
		svcs, cmds, action, err := groupRulePatches(req.Services, req.CommandRules, req.DefaultCommandAction)
		if err != nil {
			return nil, err
		}
		published, err := deps.State.UpdateGroup(req.ID, state.UpdateGroup{
			DisplayName:          req.DisplayName,
			Enabled:              req.Enabled,
			Priority:             req.Priority,
			Labels:               req.Labels,
			Services:             svcs,
			CommandRules:         cmds,
			DefaultCommandAction: action,
		}, in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		g, ok := published.Group(req.ID)
		if !ok {
			return nil, domain.NewError(domain.CodeInternal, "updated group is missing from snapshot")
		}
		audit(deps, "api.group.updated", "ok", published.Revision)
		return groupView(g, published.Revision), nil
	}
}

func handleGroupsDelete(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		if err := requireState(deps); err != nil {
			return nil, err
		}
		req, _ := in.Request.(DeleteGroupRequest)
		if err := requireID(req.ID); err != nil {
			return nil, err
		}
		published, err := deps.State.DeleteGroup(req.ID, state.DeleteOptions{
			Tombstone: req.Tombstone,
			ActorID:   in.Actor.ID,
		}, in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		audit(deps, "api.group.deleted", "ok", published.Revision)
		return DeleteResult{ID: req.ID, Revision: published.Revision}, nil
	}
}

func groupRulePatches(services *[]ServiceRuleView, commands *[]CommandRuleView, action *string) (*[]config.ServiceRule, *[]config.CommandRule, *domain.AuthorDecision, error) {
	var svcs *[]config.ServiceRule
	if services != nil {
		parsed, err := serviceRulesFromView(*services)
		if err != nil {
			return nil, nil, nil, err
		}
		svcs = &parsed
	}
	var cmds *[]config.CommandRule
	if commands != nil {
		parsed, err := commandRulesFromView(*commands)
		if err != nil {
			return nil, nil, nil, err
		}
		cmds = &parsed
	}
	dca, err := defaultCommandAction(action)
	if err != nil {
		return nil, nil, nil, err
	}
	return svcs, cmds, dca, nil
}
