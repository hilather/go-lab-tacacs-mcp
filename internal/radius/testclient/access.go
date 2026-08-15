package testclient

import (
	"io"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

// AccessRequest is a PAP or CHAP Access-Request built by the independent codec.
type AccessRequest struct {
	Identifier    uint8
	Authenticator [16]byte
	UserName      string
	Password      []byte // PAP plaintext; hidden on Encode
	CHAPPassword  []byte // 17 octets when set
	CHAPChallenge []byte
	Extra         []codec.Attr
	IncludeMA     bool
}

// AccessReply is a decoded Access-Accept/Reject/Challenge after
// Response Authenticator and Message-Authenticator checks.
type AccessReply struct {
	Code          codec.Code
	Identifier    uint8
	Authenticator [16]byte
	Attrs         []codec.Attr
}

// EncodeAccessRequest hides PAP, optionally inserts Message-Authenticator,
// and returns one datagram. password is not retained in the packet.
func EncodeAccessRequest(secret []byte, req AccessRequest, rand io.Reader) ([]byte, error) {
	if req.UserName == "" {
		return nil, ErrMissingUserName
	}
	pap := req.Password != nil
	chap := req.CHAPPassword != nil
	if pap && chap {
		return nil, ErrConflictingAuth
	}
	if chap && len(req.CHAPPassword) != 17 {
		return nil, ErrCHAPPasswordLength
	}

	var zero [16]byte
	auth := req.Authenticator
	if auth == zero {
		var err error
		auth, err = codec.NewRequestAuthenticator(rand)
		if err != nil {
			return nil, err
		}
	}

	attrs := make([]codec.Attr, 0, 4+len(req.Extra))
	attrs = append(attrs, codec.Attr{Type: codec.TypeUserName, Value: []byte(req.UserName)})
	if pap {
		hidden, err := codec.HideUserPassword(secret, auth, req.Password)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, codec.Attr{Type: codec.TypeUserPassword, Value: hidden})
	}
	if chap {
		cp := make([]byte, len(req.CHAPPassword))
		copy(cp, req.CHAPPassword)
		attrs = append(attrs, codec.Attr{Type: codec.TypeCHAPPassword, Value: cp})
		if len(req.CHAPChallenge) > 0 {
			ch := make([]byte, len(req.CHAPChallenge))
			copy(ch, req.CHAPChallenge)
			attrs = append(attrs, codec.Attr{Type: codec.TypeCHAPChallenge, Value: ch})
		}
	}
	attrs = append(attrs, codec.CloneAttrs(req.Extra)...)
	if req.IncludeMA {
		attrs = append(attrs, codec.Attr{Type: codec.TypeMessageAuthenticator, Value: make([]byte, 16)})
	}

	pkt, err := codec.Encode(codec.Packet{
		Code:          codec.AccessRequest,
		Identifier:    req.Identifier,
		Authenticator: auth,
		Attrs:         attrs,
	})
	if err != nil {
		return nil, err
	}
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

// EncodeAccessReply builds an Access-Accept/Reject/Challenge. Message-
// Authenticator is inserted first and HMAC'd with reqAuth in the header,
// then the Response Authenticator replaces the header field (RFC 2869 §5.14).
func EncodeAccessReply(secret []byte, code codec.Code, id uint8, reqAuth [16]byte, extra []codec.Attr) ([]byte, error) {
	if !code.AccessFamily() || code == codec.AccessRequest {
		return nil, ErrUnexpectedCode
	}
	return encodeSignedResponse(secret, code, id, reqAuth, extra)
}

// DecodeAccessReply decodes one Access response. Message-Authenticator is
// required and checked with the Request Authenticator substituted into the
// header. The Response Authenticator is then checked on the original packet.
func DecodeAccessReply(secret []byte, reqAuth [16]byte, packet []byte) (AccessReply, error) {
	p, err := codec.Decode(packet)
	if err != nil {
		return AccessReply{}, err
	}
	if !p.Code.AccessFamily() || p.Code == codec.AccessRequest {
		return AccessReply{}, ErrUnexpectedCode
	}
	if err := validateResponseIntegrity(secret, reqAuth, packet); err != nil {
		return AccessReply{}, err
	}
	return AccessReply{
		Code:          p.Code,
		Identifier:    p.Identifier,
		Authenticator: p.Authenticator,
		Attrs:         p.Attrs,
	}, nil
}
