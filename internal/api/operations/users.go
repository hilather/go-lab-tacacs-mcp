package operations

import (
	"context"
	"sort"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func handleUsersList(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	req, _ := in.Request.(ListUsersRequest)
	limit := normalizePage(req.Limit)
	live := snap.Users()
	type item struct {
		id   string
		user User
	}
	all := make([]item, 0, len(live))
	seen := map[string]struct{}{}
	for _, u := range live {
		all = append(all, item{id: u.User.ID, user: userView(u, snap.Revision)})
		seen[u.User.ID] = struct{}{}
	}
	if req.IncludeDeleted {
		for _, t := range tombstonesOf(snap, domain.KindUser) {
			id := string(t.ID)
			if _, ok := seen[id]; ok {
				continue
			}
			all = append(all, item{id: id, user: deletedUser(t, snap.Revision)})
		}
	}
	ids := make([]string, len(all))
	byID := make(map[string]User, len(all))
	for i, it := range all {
		ids[i] = it.id
		byID[it.id] = it.user
	}
	// live Users() is already sorted; tombstones appended — re-sort for include_deleted.
	if req.IncludeDeleted {
		sort.Strings(ids)
	}
	start, end, next := pageAfter(ids, req.Cursor, limit)
	items := make([]User, 0, end-start)
	for _, id := range ids[start:end] {
		items = append(items, byID[id])
	}
	return UserList{Revision: snap.Revision, Items: items, NextCursor: next}, nil
}

func handleUsersGet(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	req, _ := in.Request.(GetUserRequest)
	if err := requireID(req.ID); err != nil {
		return nil, err
	}
	if u, ok := snap.User(req.ID); ok {
		return userView(u, snap.Revision), nil
	}
	if req.IncludeDeleted {
		if t, ok := findTombstone(snap, domain.KindUser, req.ID); ok {
			return deletedUser(t, snap.Revision), nil
		}
	}
	return nil, domain.NewError(domain.CodeNotFound, "user not found").WithPath("users/" + req.ID)
}

func handleUsersCreate(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		if err := requireState(deps); err != nil {
			return nil, err
		}
		req, _ := in.Request.(CreateUserRequest)
		if err := requireID(req.ID); err != nil {
			return nil, err
		}
		rules, err := ruleSetFromView(req.Rules)
		if err != nil {
			return nil, err
		}
		published, err := deps.State.CreateUser(state.CreateUser{
			ID:               req.ID,
			DisplayName:      req.DisplayName,
			Enabled:          req.Enabled,
			Labels:           req.Labels,
			GroupIDs:         req.GroupIDs,
			Rules:            rules,
			Login:            req.Login.patch(),
			Challenge:        req.Challenge.patch(),
			Enable:           req.Enable.patch(),
			Restrictions:     restrictionsFromView(req.Restrictions),
			MustChangeLogin:  req.MustChangeLogin,
			MustChangeEnable: req.MustChangeEnable,
			Override:         req.Override,
		}, in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		u, ok := published.User(req.ID)
		if !ok {
			return nil, domain.NewError(domain.CodeInternal, "created user is missing from snapshot")
		}
		audit(deps, "api.user.created", "ok", published.Revision)
		return userView(u, published.Revision), nil
	}
}

func handleUsersUpdate(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		if err := requireState(deps); err != nil {
			return nil, err
		}
		req, _ := in.Request.(UpdateUserRequest)
		if err := requireID(req.ID); err != nil {
			return nil, err
		}
		rules, err := ruleSetFromView(req.Rules)
		if err != nil {
			return nil, err
		}
		published, err := deps.State.UpdateUser(req.ID, state.UpdateUser{
			DisplayName:      req.DisplayName,
			Enabled:          req.Enabled,
			Labels:           req.Labels,
			GroupIDs:         req.GroupIDs,
			Rules:            rules,
			Login:            req.Login.patch(),
			Challenge:        req.Challenge.patch(),
			Enable:           req.Enable.patch(),
			Restrictions:     restrictionsFromView(req.Restrictions),
			MustChangeLogin:  req.MustChangeLogin,
			MustChangeEnable: req.MustChangeEnable,
		}, in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		u, ok := published.User(req.ID)
		if !ok {
			return nil, domain.NewError(domain.CodeInternal, "updated user is missing from snapshot")
		}
		audit(deps, "api.user.updated", "ok", published.Revision)
		return userView(u, published.Revision), nil
	}
}

func handleUsersDelete(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		if err := requireState(deps); err != nil {
			return nil, err
		}
		req, _ := in.Request.(DeleteUserRequest)
		if err := requireID(req.ID); err != nil {
			return nil, err
		}
		published, err := deps.State.DeleteUser(req.ID, state.DeleteOptions{
			Tombstone: req.Tombstone,
			ActorID:   in.Actor.ID,
		}, in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		audit(deps, "api.user.deleted", "ok", published.Revision)
		return DeleteResult{ID: req.ID, Revision: published.Revision}, nil
	}
}
