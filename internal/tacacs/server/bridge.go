package server

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

// Bridge adapts aaa.Service to Handler. Packet types stay in this package.
type Bridge struct {
	AAA *aaa.Service
}

var _ Handler = Bridge{}

// AuthenStart translates a START packet into the AAA conversation.
func (b Bridge) AuthenStart(ctx context.Context, env Env, start codec.AuthenStart) (codec.AuthenReply, error) {
	if b.AAA == nil {
		return codec.AuthenReply{Status: codec.AuthenStatusError}, nil
	}
	step, err := b.AAA.BeginAuthentication(ctx, aaa.AuthenticationStart{
		ConnKey:   env.ConnKey,
		SessionID: env.SessionID,
		UserID:    string(start.User),
		ClientID:  env.ClientID,
		Action:    domain.AuthenAction(start.Action),
		Type:      domain.AuthenType(start.Type),
		Service:   domain.AuthenService(start.Service),
		PrivLvl:   start.PrivLvl,
		Port:      string(start.Port),
		Remote:    string(start.RemAddr),
		Data:      start.Data,
		Revision:  env.Revision,
		Transport: env.Transport,
	})
	if err != nil {
		return codec.AuthenReply{Status: codec.AuthenStatusError}, nil
	}
	return mapAuthen(step), nil
}

// AuthenContinue translates a CONTINUE packet.
func (b Bridge) AuthenContinue(ctx context.Context, env Env, cont codec.AuthenContinue) (codec.AuthenReply, error) {
	if b.AAA == nil {
		return codec.AuthenReply{Status: codec.AuthenStatusError}, nil
	}
	if cont.Abort() {
		_ = b.AAA.AbortAuthentication(ctx, aaa.AuthenticationAbort{
			ConnKey:   env.ConnKey,
			SessionID: env.SessionID,
			ClientID:  env.ClientID,
			Revision:  env.Revision,
		})
		return codec.AuthenReply{Status: codec.AuthenStatusFail}, nil
	}
	step, err := b.AAA.ContinueAuthentication(ctx, aaa.AuthenticationContinue{
		ConnKey:   env.ConnKey,
		SessionID: env.SessionID,
		UserMsg:   cont.UserMsg,
		ClientID:  env.ClientID,
		Revision:  env.Revision,
		Transport: env.Transport,
	})
	if err != nil {
		return codec.AuthenReply{Status: codec.AuthenStatusError}, nil
	}
	return mapAuthen(step), nil
}

// Authorize translates an authorization request through the two evaluators.
func (b Bridge) Authorize(ctx context.Context, env Env, req codec.AuthorRequest) (codec.AuthorResponse, error) {
	if b.AAA == nil {
		return codec.AuthorResponse{Status: codec.AuthorStatusError}, nil
	}
	dec, err := b.AAA.Authorize(ctx, aaa.AuthorizationRequest{
		UserID:        string(req.User),
		ClientID:      env.ClientID,
		Arguments:     argsToAV(req.Args),
		AuthenMethod:  domain.AuthenMethod(req.AuthenMethod),
		AuthenType:    domain.AuthenType(req.AuthenType),
		AuthenService: domain.AuthenService(req.Service),
		Privilege:     domain.PrivilegeLevel(req.PrivLvl),
		Port:          string(req.Port),
		Remote:        string(req.RemAddr),
		Revision:      env.Revision,
		Transport:     env.Transport,
		SessionID:     env.SessionID,
	})
	if err != nil {
		return codec.AuthorResponse{Status: codec.AuthorStatusError}, nil
	}
	return codec.AuthorResponse{Status: byte(dec.Status), Args: avToArgs(dec.Arguments)}, nil
}

// Account accepts a valid record into the event ring.
func (b Bridge) Account(ctx context.Context, env Env, req codec.AcctRequest) (codec.AcctReply, error) {
	if b.AAA == nil {
		return codec.AcctReply{Status: codec.AcctStatusError}, nil
	}
	res, err := b.AAA.RecordAccounting(ctx, aaa.AccountingRecord{
		Flags:     req.Flags,
		UserID:    string(req.User),
		ClientID:  env.ClientID,
		SessionID: env.SessionID,
		Arguments: argsToAV(req.Args),
		Revision:  env.Revision,
		Transport: env.Transport,
		Port:      string(req.Port),
		Remote:    string(req.RemAddr),
	})
	if err != nil || !res.OK {
		return codec.AcctReply{Status: codec.AcctStatusError}, nil
	}
	return codec.AcctReply{Status: codec.AcctStatusSuccess}, nil
}

// EndSession drops AAA conversation state on TACACS session teardown.
func (b Bridge) EndSession(ctx context.Context, env Env) {
	if b.AAA == nil {
		return
	}
	_ = b.AAA.AbortAuthentication(ctx, aaa.AuthenticationAbort{
		ConnKey:   env.ConnKey,
		SessionID: env.SessionID,
		ClientID:  env.ClientID,
		Revision:  env.Revision,
	})
}

func mapAuthen(step aaa.AuthenticationStep) codec.AuthenReply {
	r := codec.AuthenReply{Status: byte(step.Status)}
	if step.NoEcho {
		r.Flags = codec.ReplyFlagNoEcho
	}
	if step.ServerMsg != "" {
		r.ServerMsg = []byte(step.ServerMsg)
	}
	return r
}

func argsToAV(in []codec.Argument) domain.AVPairs {
	out := make(domain.AVPairs, 0, len(in))
	for _, a := range in {
		out = append(out, domain.AVPair{Name: a.Name, Separator: a.Separator, Value: a.Value})
	}
	return out
}

func avToArgs(in domain.AVPairs) []codec.Argument {
	out := make([]codec.Argument, 0, len(in))
	for _, a := range in {
		out = append(out, codec.Argument{Name: a.Name, Separator: a.Separator, Value: a.Value})
	}
	return out
}
