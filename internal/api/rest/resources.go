package rest

import (
	"net/http"
	"strconv"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	req, err := listObjectQuery[operations.ListUsersRequest](r, func(cursor string, limit int, deleted bool) operations.ListUsersRequest {
		return operations.ListUsersRequest{Cursor: cursor, Limit: limit, IncludeDeleted: deleted}
	})
	if err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDUsersList, req, false)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	deleted, err := parseBoolQuery(r, "include_deleted")
	if err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDUsersGet, operations.GetUserRequest{ID: r.PathValue("id"), IncludeDeleted: deleted}, false)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req operations.CreateUserRequest
	if err := decodeJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDUsersCreate, req, true)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var req operations.UpdateUserRequest
	if err := decodeJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	req.ID = r.PathValue("id")
	s.invoke(w, r, operations.IDUsersUpdate, req, true)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	req := operations.DeleteUserRequest{ID: r.PathValue("id")}
	tomb, err := parseBoolQuery(r, "tombstone")
	if err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	req.Tombstone = tomb
	s.invoke(w, r, operations.IDUsersDelete, req, true)
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	req, err := listObjectQuery[operations.ListGroupsRequest](r, func(cursor string, limit int, deleted bool) operations.ListGroupsRequest {
		return operations.ListGroupsRequest{Cursor: cursor, Limit: limit, IncludeDeleted: deleted}
	})
	if err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDGroupsList, req, false)
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	deleted, err := parseBoolQuery(r, "include_deleted")
	if err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDGroupsGet, operations.GetGroupRequest{ID: r.PathValue("id"), IncludeDeleted: deleted}, false)
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var req operations.CreateGroupRequest
	if err := decodeJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDGroupsCreate, req, true)
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	var req operations.UpdateGroupRequest
	if err := decodeJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	req.ID = r.PathValue("id")
	s.invoke(w, r, operations.IDGroupsUpdate, req, true)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	req := operations.DeleteGroupRequest{ID: r.PathValue("id")}
	tomb, err := parseBoolQuery(r, "tombstone")
	if err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	req.Tombstone = tomb
	s.invoke(w, r, operations.IDGroupsDelete, req, true)
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	req, err := listObjectQuery[operations.ListClientsRequest](r, func(cursor string, limit int, deleted bool) operations.ListClientsRequest {
		return operations.ListClientsRequest{Cursor: cursor, Limit: limit, IncludeDeleted: deleted}
	})
	if err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDClientsList, req, false)
}

func (s *Server) getClient(w http.ResponseWriter, r *http.Request) {
	deleted, err := parseBoolQuery(r, "include_deleted")
	if err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDClientsGet, operations.GetClientRequest{ID: r.PathValue("id"), IncludeDeleted: deleted}, false)
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	var req operations.CreateClientRequest
	if err := decodeJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDClientsCreate, req, true)
}

func (s *Server) updateClient(w http.ResponseWriter, r *http.Request) {
	var req operations.UpdateClientRequest
	if err := decodeJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	req.ID = r.PathValue("id")
	s.invoke(w, r, operations.IDClientsUpdate, req, true)
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	req := operations.DeleteClientRequest{ID: r.PathValue("id")}
	tomb, err := parseBoolQuery(r, "tombstone")
	if err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	req.Tombstone = tomb
	s.invoke(w, r, operations.IDClientsDelete, req, true)
}

func (s *Server) effectiveConfig(w http.ResponseWriter, r *http.Request) {
	s.invoke(w, r, operations.IDConfigEffectiveGet, operations.GetEffectiveConfigRequest{View: r.URL.Query().Get("view")}, false)
}

func (s *Server) validateConfig(w http.ResponseWriter, r *http.Request) {
	var req operations.ValidateConfigRequest
	if err := decodeOptionalJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDConfigValidate, req, false)
}

func (s *Server) reloadConfig(w http.ResponseWriter, r *http.Request) {
	var req operations.ReloadConfigRequest
	if err := decodeOptionalJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDConfigReload, req, true)
}

func (s *Server) exportConfig(w http.ResponseWriter, r *http.Request) {
	normalize, err := parseBoolQuery(r, "normalize")
	if err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDConfigExport, operations.ExportConfigRequest{
		View:      r.URL.Query().Get("view"),
		Normalize: normalize,
	}, false)
}

func (s *Server) resetRuntime(w http.ResponseWriter, r *http.Request) {
	var req operations.ResetRuntimeRequest
	if err := decodeOptionalJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDRuntimeReset, req, true)
}

func (s *Server) testAuthentication(w http.ResponseWriter, r *http.Request) {
	var req operations.TestAuthenticationRequest
	if err := decodeJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDAuthenticationTest, req, false)
}

func (s *Server) testRadiusAccess(w http.ResponseWriter, r *http.Request) {
	var req operations.RadiusAccessTestRequest
	if err := decodeJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDRadiusAccessTest, req, false)
}

func (s *Server) evaluateRadiusPolicy(w http.ResponseWriter, r *http.Request) {
	var req operations.RadiusPolicyEvaluateRequest
	if err := decodeJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDRadiusPolicyEvaluate, req, false)
}

func (s *Server) listRadiusAttributes(w http.ResponseWriter, r *http.Request) {
	s.invoke(w, r, operations.IDRadiusAttributesList, operations.ListRadiusAttributesRequest{}, false)
}

func listObjectQuery[T any](r *http.Request, build func(cursor string, limit int, deleted bool) T) (T, error) {
	var zero T
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return zero, domain.NewError(domain.CodeInvalidArgument, "invalid limit")
		}
		limit = n
	}
	deleted, err := parseBoolQuery(r, "include_deleted")
	if err != nil {
		return zero, err
	}
	return build(r.URL.Query().Get("cursor"), limit, deleted), nil
}

func parseBoolQuery(r *http.Request, name string) (bool, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, domain.NewError(domain.CodeInvalidArgument, "invalid "+name)
	}
	return v, nil
}
