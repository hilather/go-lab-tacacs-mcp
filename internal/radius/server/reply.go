package server

import (
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

// SignResponse builds an Access or Accounting response: Message-Authenticator
// is the first attribute (zeroed during HMAC), then rest (Proxy-State and
// later policy attrs), then the Response Authenticator over the signed attrs.
func SignResponse(secret []byte, code codec.Code, id uint8, reqAuth [16]byte, rest attribute.RawSet) ([]byte, error) {
	if len(secret) == 0 {
		return nil, crypto.ErrEmptySecret
	}
	attrs := make(attribute.RawSet, 0, 1+rest.Len())
	attrs = append(attrs, attribute.Raw{
		Type:  attribute.TypeMessageAuthenticator,
		Value: make([]byte, codec.AuthenticatorSize),
	})
	attrs = append(attrs, rest...)
	wire, err := codec.Encode(codec.Packet{
		Code:          code,
		Identifier:    id,
		Authenticator: reqAuth,
		Attributes:    attrs,
	})
	if err != nil {
		return nil, err
	}
	mac, err := crypto.MessageAuthenticator(secret, wire)
	if err != nil {
		return nil, err
	}
	off := codec.HeaderSize
	if len(wire) < off+2+codec.AuthenticatorSize || wire[off] != attribute.TypeMessageAuthenticator || wire[off+1] != 18 {
		return nil, crypto.ErrInvalidMessageAuthenticator
	}
	copy(wire[off+2:off+18], mac[:])
	attrs[0].Value = append([]byte(nil), mac[:]...)
	ra, err := crypto.ResponseAuthenticator(secret, code, id, 0, reqAuth, attrs)
	if err != nil {
		return nil, err
	}
	copy(wire[4:20], ra[:])
	return wire, nil
}

// CopyProxyState returns request Proxy-State attributes in order, unmodified.
func CopyProxyState(in attribute.RawSet) attribute.RawSet {
	found := in.AllOf(attribute.TypeProxyState)
	if found.Len() == 0 {
		return nil
	}
	return found.Clone()
}
