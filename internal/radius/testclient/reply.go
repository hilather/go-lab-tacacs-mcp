package testclient

import "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"

// encodeSignedResponse inserts Message-Authenticator first, HMACs it with
// reqAuth in the header, then replaces the header with the Response
// Authenticator (RFC 2869 §5.14 / RFC 3579 §3.2).
func encodeSignedResponse(secret []byte, code codec.Code, id uint8, reqAuth [16]byte, extra []codec.Attr) ([]byte, error) {
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
	if err := codec.PutMessageAuthenticator(pkt, mac); err != nil {
		return nil, err
	}
	macVal := make([]byte, 16)
	copy(macVal, mac[:])
	attrs[0].Value = macVal
	resp, err := codec.ResponseAuthenticator(secret, code, id, reqAuth, attrs)
	if err != nil {
		return nil, err
	}
	copy(pkt[4:20], resp[:])
	return pkt, nil
}

// validateResponseIntegrity checks Message-Authenticator after substituting
// the Request Authenticator, then checks the Response Authenticator on the
// original datagram.
func validateResponseIntegrity(secret []byte, reqAuth [16]byte, packet []byte) error {
	forMA, err := codec.WithAuthenticator(packet, reqAuth)
	if err != nil {
		return err
	}
	if err := codec.ValidateMessageAuthenticator(secret, forMA); err != nil {
		return ErrInvalidMessageAuthenticator
	}
	if err := codec.ValidateResponseAuthenticator(secret, packet, reqAuth); err != nil {
		return ErrInvalidResponseAuthenticator
	}
	return nil
}
