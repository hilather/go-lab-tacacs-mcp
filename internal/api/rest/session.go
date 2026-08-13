package rest

import (
	"net/http"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	rid := requestIDFrom(r)
	if s.Registry == nil || s.Auth == nil {
		writeProblemID(w, http.StatusServiceUnavailable, domain.NewError(domain.CodeUnavailable, "session service is not configured"), rid)
		return
	}
	raw, ok := auth.ParseBearer(r.Header.Get("Authorization"))
	snap := s.snap()
	if !ok {
		if lerr := s.limit(operations.Actor{}, snap); lerr != nil {
			writeDomainID(w, lerr, rid)
			return
		}
		writeDomainID(w, domain.NewError(domain.CodeUnauthenticated, "authentication required"), rid)
		return
	}
	p, err := s.Auth.VerifyBearer([]byte(raw), snap)
	if err != nil {
		if lerr := s.limit(operations.Actor{}, snap); lerr != nil {
			writeDomainID(w, lerr, rid)
			return
		}
		writeDomainID(w, err, rid)
		return
	}
	if err := s.limit(p.Actor(), snap); err != nil {
		writeDomainID(w, err, rid)
		return
	}
	if r.ContentLength > 0 {
		var req operations.CreateSessionRequest
		if err := decodeJSON(r, &req, s.maxBody()); err != nil {
			writeDomainID(w, err, rid)
			return
		}
	}
	res, err := s.Registry.Invoke(r.Context(), operations.IDSessionCreate, snap, operations.Input{
		Actor:   p.Actor(),
		Request: operations.CreateSessionRequest{},
	})
	if err != nil {
		writeDomainID(w, err, rid)
		return
	}
	sess, ok := res.Data.(operations.Session)
	if !ok {
		writeDomainID(w, domain.NewError(domain.CodeInternal, "unexpected session type"), rid)
		return
	}
	http.SetCookie(w, auth.SessionCookie(sess))
	http.SetCookie(w, auth.CSRFSetCookie(sess))
	w.Header().Set(headerETag, etag(res.Revision))
	writeJSON(w, http.StatusOK, envelope{Revision: uint64(res.Revision), RequestID: rid, Data: sess})
}

func (s *Server) deleteSessionClear(w http.ResponseWriter, r *http.Request) {
	rid := requestIDFrom(r)
	if s.Registry == nil {
		writeProblemID(w, http.StatusServiceUnavailable, domain.NewError(domain.CodeUnavailable, "operation registry is not initialized"), rid)
		return
	}
	actor, snap, err := s.authenticate(r, true)
	if err != nil {
		if lerr := s.limit(operations.Actor{}, snap); lerr != nil {
			writeDomainID(w, lerr, rid)
			return
		}
		writeDomainID(w, err, rid)
		return
	}
	if err := s.limit(actor, snap); err != nil {
		writeDomainID(w, err, rid)
		return
	}
	req := operations.DeleteSessionRequest{}
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req, s.maxBody()); err != nil {
			writeDomainID(w, err, rid)
			return
		}
	}
	res, err := s.Registry.Invoke(r.Context(), operations.IDSessionDelete, snap, operations.Input{
		Actor:   actor,
		Request: req,
	})
	if err != nil {
		writeDomainID(w, err, rid)
		return
	}
	clear := &http.Cookie{Name: auth.CookieName, Path: "/", MaxAge: -1, HttpOnly: true}
	if snap != nil && snap.Settings() != nil {
		clear.Secure = snap.Settings().API.UISession.CookieSecure
	}
	http.SetCookie(w, clear)
	csrf := &http.Cookie{Name: auth.CSRFCookieName, Path: "/", MaxAge: -1}
	csrf.Secure = clear.Secure
	http.SetCookie(w, csrf)
	w.Header().Set(headerETag, etag(res.Revision))
	writeJSON(w, http.StatusOK, envelope{Revision: uint64(res.Revision), RequestID: rid, Data: res.Data})
}

func (s *Server) snap() *state.Snapshot {
	if s.Snapshot == nil {
		return nil
	}
	return s.Snapshot()
}
