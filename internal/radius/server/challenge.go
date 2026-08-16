package server

import (
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
)

// requestCarrier is the Request carrier, defaulting to RADIUS/UDP for
// existing callers that have not filled the field.
func requestCarrier(in Request) domain.Carrier {
	if in.Carrier != "" {
		return in.Carrier
	}
	return domain.CarrierRADIUSUDP
}

// extractState copies the State attribute if present. Duplicate or empty
// State is reject_invalid_state. The raw value is never logged.
func extractState(attrs attribute.RawSet) (state []byte, present bool, reason string) {
	all := attrs.AllOf(attribute.TypeState)
	if all.Len() == 0 {
		return nil, false, ""
	}
	if all.Len() != 1 || len(all[0].Value) == 0 {
		return nil, true, ReasonInvalidState
	}
	return append([]byte(nil), all[0].Value...), true, ""
}

// bindFromRequest builds the tagged bind from Carrier. UDP uses peer IP
// (port is ignored). TLS uses the injected certificate fingerprint.
func bindFromRequest(in Request) (runtime.ChallengeBind, string) {
	switch requestCarrier(in) {
	case domain.CarrierRADIUSTLS:
		if in.TLSCertFP == [32]byte{} {
			return runtime.ChallengeBind{}, ReasonChallengeBinding
		}
		return runtime.ChallengeBind{Kind: runtime.BindTLSCert, CertFP: in.TLSCertFP}, ""
	default:
		ip := in.Peer.Addr()
		if !ip.IsValid() {
			return runtime.ChallengeBind{}, ReasonChallengeBinding
		}
		return runtime.ChallengeBind{Kind: runtime.BindUDPIP, SourceIP: ip}, ""
	}
}

// IssueChallenge stores adapter-generated State. The live Access handler
// does not call this; PR 3 is the first production issuer.
func IssueChallenge(store *runtime.ChallengeStore, in Request, rec runtime.ChallengeIssue) string {
	if store == nil {
		return ReasonChallengeCapacity
	}
	if rec.EndpointID == "" {
		rec.EndpointID = in.EndpointID
	}
	if rec.ClientID == "" {
		rec.ClientID = in.ClientID
	}
	if rec.Revision == 0 {
		rec.Revision = in.Revision
	}
	switch store.Issue(rec) {
	case runtime.IssueOK:
		return ""
	case runtime.IssueSaturated:
		return ReasonChallengeCapacity
	case runtime.IssueExists:
		return ReasonInvalidState
	default:
		return ReasonInvalidState
	}
}

// consumeContinuation looks up and consumes State. An empty reason is a hit.
func consumeContinuation(store *runtime.ChallengeStore, in Request, state []byte) (runtime.ChallengeRecord, string) {
	if store == nil {
		return runtime.ChallengeRecord{}, ReasonInvalidState
	}
	bind, reason := bindFromRequest(in)
	if reason != "" {
		return runtime.ChallengeRecord{}, reason
	}
	rec, res := store.Consume(in.EndpointID, state, in.ClientID, bind)
	switch res {
	case runtime.ConsumeOK:
		return rec, ""
	case runtime.ConsumeExpired:
		return runtime.ChallengeRecord{}, ReasonChallengeExpired
	case runtime.ConsumeBinding:
		return runtime.ChallengeRecord{}, ReasonChallengeBinding
	default:
		return runtime.ChallengeRecord{}, ReasonInvalidState
	}
}
