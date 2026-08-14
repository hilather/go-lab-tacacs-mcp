package server

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

// Action is the wire outcome after decode.
type Action uint8

const (
	// ActionDiscard sends nothing and must not mutate the retransmission cache.
	ActionDiscard Action = iota
	// ActionReply sends Response and may cache the exact bytes.
	ActionReply
)

// Request is one decoded datagram plus the endpoint secret selected by source IP.
type Request struct {
	Role       domain.ListenerRole
	Packet     codec.Packet
	Declared   []byte
	Secret     []byte
	ClientID   string
	EndpointID string
	Revision   domain.Revision
}

// Result is discard or a fully signed reply.
type Result struct {
	Action   Action
	Reason   string
	Response []byte
}

// Handler turns one request into a discard or signed reply.
type Handler interface {
	Handle(ctx context.Context, in Request) Result
}

// Stub always Access-Rejects / Accounting-Responses after decode.
// Inbound Message-Authenticator policy is skipped (later). Accounting
// Request Authenticator is still validated so a bad MAC cannot be acked.
type Stub struct{}

// Handle implements Handler.
func (Stub) Handle(ctx context.Context, in Request) Result {
	if ctx != nil && ctx.Err() != nil {
		return Result{Action: ActionDiscard, Reason: ReasonOverload}
	}
	switch in.Role {
	case domain.RoleAccess:
		if in.Packet.Code != codec.CodeAccessRequest {
			return Result{Action: ActionDiscard, Reason: ReasonInvalidCode}
		}
		wire, err := SignResponse(in.Secret, codec.CodeAccessReject, in.Packet.Identifier, in.Packet.Authenticator, CopyProxyState(in.Packet.Attributes))
		if err != nil {
			return Result{Action: ActionDiscard, Reason: ReasonMalformedHeader}
		}
		return Result{Action: ActionReply, Reason: ReasonUnsupportedMethod, Response: wire}
	case domain.RoleAccounting:
		if in.Packet.Code != codec.CodeAccountingRequest {
			return Result{Action: ActionDiscard, Reason: ReasonInvalidCode}
		}
		if err := crypto.ValidateAccountingRequestAuthenticator(in.Secret, in.Declared); err != nil {
			return Result{Action: ActionDiscard, Reason: ReasonInvalidAcctAuth}
		}
		wire, err := SignResponse(in.Secret, codec.CodeAccountingResponse, in.Packet.Identifier, in.Packet.Authenticator, CopyProxyState(in.Packet.Attributes))
		if err != nil {
			return Result{Action: ActionDiscard, Reason: ReasonMalformedHeader}
		}
		return Result{Action: ActionReply, Reason: ReasonOK, Response: wire}
	default:
		return Result{Action: ActionDiscard, Reason: ReasonInvalidCode}
	}
}
