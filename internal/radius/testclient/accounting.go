package testclient

import "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"

// Acct-Status-Type values used by the independent client (RFC 2866 / 2869).
const (
	AcctStart         uint32 = 1
	AcctStop          uint32 = 2
	AcctInterimUpdate uint32 = 3
	AcctOn            uint32 = 7
	AcctOff           uint32 = 8
)

// AccountingRequest is an Accounting-Request built by the independent codec.
type AccountingRequest struct {
	Identifier uint8
	StatusType uint32
	SessionID  string
	Extra      []codec.Attr
	IncludeMA  bool
}

// AccountingResponse is a decoded Accounting-Response after authenticator
// and Message-Authenticator checks.
type AccountingResponse struct {
	Identifier    uint8
	Authenticator [16]byte
	Attrs         []codec.Attr
}

// EncodeAccountingRequest writes the Accounting-Request Authenticator.
// When IncludeMA is set, the authenticator is computed with a zeroed MA
// value, then MA is filled. Do not recompute the authenticator after MA.
func EncodeAccountingRequest(secret []byte, req AccountingRequest) ([]byte, error) {
	attrs := make([]codec.Attr, 0, 3+len(req.Extra))
	st := []byte{
		byte(req.StatusType >> 24),
		byte(req.StatusType >> 16),
		byte(req.StatusType >> 8),
		byte(req.StatusType),
	}
	attrs = append(attrs, codec.Attr{Type: codec.TypeAcctStatusType, Value: st})
	if req.SessionID != "" {
		attrs = append(attrs, codec.Attr{Type: codec.TypeAcctSessionID, Value: []byte(req.SessionID)})
	}
	attrs = append(attrs, codec.CloneAttrs(req.Extra)...)
	if req.IncludeMA {
		attrs = append(attrs, codec.Attr{Type: codec.TypeMessageAuthenticator, Value: make([]byte, 16)})
	}

	pkt, err := codec.Encode(codec.Packet{
		Code:       codec.AccountingRequest,
		Identifier: req.Identifier,
		Attrs:      attrs,
	})
	if err != nil {
		return nil, err
	}
	auth, err := codec.AccountingRequestAuthenticator(secret, pkt)
	if err != nil {
		return nil, err
	}
	copy(pkt[4:20], auth[:])
	if req.IncludeMA {
		mac, err := codec.MessageAuthenticator(secret, pkt)
		if err != nil {
			return nil, err
		}
		if err := codec.PutMessageAuthenticator(pkt, mac); err != nil {
			return nil, err
		}
	}
	return pkt, nil
}

// DecodeAccountingResponse requires a valid Response Authenticator and
// a valid Message-Authenticator.
func DecodeAccountingResponse(secret []byte, reqAuth [16]byte, packet []byte) (AccountingResponse, error) {
	p, err := codec.Decode(packet)
	if err != nil {
		return AccountingResponse{}, err
	}
	if p.Code != codec.AccountingResponse {
		return AccountingResponse{}, ErrUnexpectedCode
	}
	if err := codec.ValidateMessageAuthenticator(secret, packet); err != nil {
		return AccountingResponse{}, ErrInvalidMessageAuthenticator
	}
	if err := codec.ValidateResponseAuthenticator(secret, packet, reqAuth); err != nil {
		return AccountingResponse{}, ErrInvalidResponseAuthenticator
	}
	return AccountingResponse{
		Identifier:    p.Identifier,
		Authenticator: p.Authenticator,
		Attrs:         p.Attrs,
	}, nil
}
