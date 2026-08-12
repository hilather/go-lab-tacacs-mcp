package server

import (
	"context"
	"net"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

// Identity is the client binding for a connection's lifetime. Reload does
// not retarget an accepted connection.
type Identity struct {
	ClientID  string
	Transport domain.Transport
	Peer      net.IP
	Revision  domain.Revision
}

// Env is the sanitized per-packet view passed to Handler.
type Env struct {
	Identity
	SessionID uint32
	// ConnKey is unique per accepted connection so ASCII conversations
	// from different peers cannot share session_id state.
	ConnKey uint64
}

// Handler is the AAA hook. Full ASCII/PAP/CHAP conversations are owned by
// later work; a stub is enough to exercise decode, match, and sessions.
// Implementations must not put secrets or internal error text on the wire.
type Handler interface {
	AuthenStart(ctx context.Context, env Env, start codec.AuthenStart) (codec.AuthenReply, error)
	AuthenContinue(ctx context.Context, env Env, cont codec.AuthenContinue) (codec.AuthenReply, error)
	Authorize(ctx context.Context, env Env, req codec.AuthorRequest) (codec.AuthorResponse, error)
	Account(ctx context.Context, env Env, req codec.AcctRequest) (codec.AcctReply, error)
}

// SessionFinalizer is optional. Bridge uses it to drop AAA conversation
// state when a TACACS session ends without CONTINUE ABORT (TCP drop, idle).
type SessionFinalizer interface {
	EndSession(ctx context.Context, env Env)
}

// Stub answers every well-formed packet with a protocol-legal terminal
// status so the listener can be tested without a real AAA service.
type Stub struct{}

// AuthenStart returns ERROR: the flow is classified, but no conversation
// is implemented here.
func (Stub) AuthenStart(context.Context, Env, codec.AuthenStart) (codec.AuthenReply, error) {
	return codec.AuthenReply{Status: codec.AuthenStatusError}, nil
}

// AuthenContinue terminates the stub conversation.
func (Stub) AuthenContinue(_ context.Context, _ Env, cont codec.AuthenContinue) (codec.AuthenReply, error) {
	if cont.Abort() {
		return codec.AuthenReply{Status: codec.AuthenStatusFail}, nil
	}
	return codec.AuthenReply{Status: codec.AuthenStatusError}, nil
}

// Authorize default-denies. Policy evaluation is a later package.
func (Stub) Authorize(context.Context, Env, codec.AuthorRequest) (codec.AuthorResponse, error) {
	return codec.AuthorResponse{Status: codec.AuthorStatusFail}, nil
}

// Account accepts a valid flag combination into the stub sink.
func (Stub) Account(_ context.Context, _ Env, req codec.AcctRequest) (codec.AcctReply, error) {
	if !codec.ValidAcctFlags(req.Flags) {
		return codec.AcctReply{Status: codec.AcctStatusError}, nil
	}
	return codec.AcctReply{Status: codec.AcctStatusSuccess}, nil
}

var _ Handler = Stub{}
