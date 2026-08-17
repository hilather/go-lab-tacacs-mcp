package aaa

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func appendMSCHAP2Success(s *Service, ctx context.Context, snap *state.Snapshot, clientID, user string, ev *CredentialEvidence, dec *RadiusAccessDecision) error {
	if s == nil || ev == nil || dec == nil {
		return credentials.ErrInvalid
	}
	if len(ev.Response) < credentials.MSCHAPResponseLen {
		return credentials.ErrMalformed
	}
	peer := ev.Response[:16]
	creds := s.boundCreds(snap, clientID)
	success, err := creds.MSCHAPv2Success(ctx, user, ev.CHAPID, ev.Challenge, peer)
	if err != nil {
		return err
	}
	raw, err := attribute.MicrosoftVSA(attribute.VendorTypeMSCHAP2Success, success)
	wipeMSCHAPBytes(success)
	if err != nil {
		return err
	}
	dec.ReplyAttributes = append(attribute.RawSet{raw}, dec.ReplyAttributes...)
	return nil
}

func wipeMSCHAPEvidence(ev *CredentialEvidence) {
	if ev == nil {
		return
	}
	wipeMSCHAPBytes(ev.Challenge)
	wipeMSCHAPBytes(ev.Response)
}

func wipeMSCHAPBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
