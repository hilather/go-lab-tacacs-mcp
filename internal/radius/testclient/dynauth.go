package testclient

import (
	"io"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

// DynAuthRequest is an independent CoA/Disconnect-Request.
type DynAuthRequest struct {
	Code          codec.Code
	Identifier    uint8
	Authenticator [16]byte
	UserName      string
	AcctSessionID string
	Extra         []codec.Attr
}

// DynAuthReply is an independent ACK/NAK after MA and Response Authenticator checks.
type DynAuthReply struct {
	Code          codec.Code
	Identifier    uint8
	Authenticator [16]byte
	ErrorCause    uint32
	Attrs         []codec.Attr
}

// EncodeDynAuthRequest inserts Message-Authenticator first and returns one datagram.
func EncodeDynAuthRequest(secret []byte, req DynAuthRequest, rand io.Reader) ([]byte, error) {
	if req.Code != codec.CoARequest && req.Code != codec.DisconnectRequest {
		return nil, ErrUnexpectedCode
	}
	auth := req.Authenticator
	var zero [16]byte
	if auth == zero {
		var err error
		auth, err = codec.NewRequestAuthenticator(rand)
		if err != nil {
			return nil, err
		}
	}
	attrs := make([]codec.Attr, 0, 4+len(req.Extra))
	attrs = append(attrs, codec.Attr{Type: codec.TypeMessageAuthenticator, Value: make([]byte, 16)})
	if req.UserName != "" {
		attrs = append(attrs, codec.Attr{Type: codec.TypeUserName, Value: []byte(req.UserName)})
	}
	if req.AcctSessionID != "" {
		attrs = append(attrs, codec.Attr{Type: codec.TypeAcctSessionID, Value: []byte(req.AcctSessionID)})
	}
	attrs = append(attrs, codec.CloneAttrs(req.Extra)...)
	pkt, err := codec.Encode(codec.Packet{
		Code:          req.Code,
		Identifier:    req.Identifier,
		Authenticator: auth,
		Attrs:         attrs,
	})
	if err != nil {
		return nil, err
	}
	mac, err := codec.MessageAuthenticator(secret, pkt)
	if err != nil {
		return nil, err
	}
	copy(pkt[codec.HeaderLen+2:codec.HeaderLen+18], mac[:])
	return pkt, nil
}

// DecodeDynAuthRequest validates MA and returns the independent packet.
func DecodeDynAuthRequest(secret []byte, wire []byte) (codec.Packet, error) {
	if err := codec.ValidateMessageAuthenticator(secret, wire); err != nil {
		return codec.Packet{}, err
	}
	pkt, err := codec.Decode(wire)
	if err != nil {
		return codec.Packet{}, err
	}
	if !pkt.Code.DynamicAuthFamily() {
		return codec.Packet{}, ErrUnexpectedCode
	}
	return pkt, nil
}

// EncodeDynAuthReply builds ACK/NAK with MA first and Response Authenticator.
func EncodeDynAuthReply(secret []byte, code codec.Code, id uint8, reqAuth [16]byte, extra []codec.Attr) ([]byte, error) {
	if code != codec.CoAACK && code != codec.CoANAK && code != codec.DisconnectACK && code != codec.DisconnectNAK {
		return nil, ErrUnexpectedCode
	}
	attrs := make([]codec.Attr, 0, 1+len(extra))
	attrs = append(attrs, codec.Attr{Type: codec.TypeMessageAuthenticator, Value: make([]byte, 16)})
	attrs = append(attrs, codec.CloneAttrs(extra)...)
	pkt, err := codec.Encode(codec.Packet{
		Code:          code,
		Identifier:    id,
		Authenticator: reqAuth,
		Attrs:         attrs,
	})
	if err != nil {
		return nil, err
	}
	mac, err := codec.MessageAuthenticator(secret, pkt)
	if err != nil {
		return nil, err
	}
	copy(pkt[codec.HeaderLen+2:codec.HeaderLen+18], mac[:])
	ra, err := codec.ResponseAuthenticator(secret, code, id, reqAuth, attrsWithMAC(attrs, mac))
	if err != nil {
		return nil, err
	}
	copy(pkt[4:20], ra[:])
	return pkt, nil
}

func attrsWithMAC(in []codec.Attr, mac [16]byte) []codec.Attr {
	out := codec.CloneAttrs(in)
	for i := range out {
		if out[i].Type == codec.TypeMessageAuthenticator {
			out[i].Value = append([]byte(nil), mac[:]...)
		}
	}
	return out
}
