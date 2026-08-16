package server

import (
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

// CheckIntegrity runs the endpoint-authoritative MA / limit_proxy_state
// algorithm (design §5.3.1). A non-empty reason is a silent discard and
// must not read, insert, or purge the retransmission cache.
func CheckIntegrity(in Request) string {
	switch in.Role {
	case domain.RoleAccess:
		return checkAccessIntegrity(in)
	case domain.RoleAccounting:
		return checkAccountingMA(in)
	case domain.RoleDynamicAuthorization:
		return checkDynAuthIntegrity(in)
	default:
		return ReasonInvalidCode
	}
}

func checkDynAuthIntegrity(in Request) string {
	mas := in.Packet.Attributes.AllOf(attribute.TypeMessageAuthenticator)
	if mas.Len() > 1 {
		return ReasonInvalidMA
	}
	declared := declaredPacket(in)
	if len(declared) == 0 {
		return ReasonMalformedHeader
	}
	if mas.Len() == 0 {
		return ReasonMissingMA
	}
	if err := crypto.ValidateMessageAuthenticator(in.Secret, declared); err != nil {
		return ReasonInvalidMA
	}
	return ""
}

func checkAccessIntegrity(in Request) string {
	mas := in.Packet.Attributes.AllOf(attribute.TypeMessageAuthenticator)
	if mas.Len() > 1 {
		return ReasonInvalidMA
	}
	declared := declaredPacket(in)
	if len(declared) == 0 {
		return ReasonMalformedHeader
	}

	maValid := false
	if mas.Len() == 1 {
		if err := crypto.ValidateMessageAuthenticator(in.Secret, declared); err != nil {
			return ReasonInvalidMA
		}
		maValid = true
	}

	if in.Packet.Attributes.AllOf(attribute.TypeEAPMessage).Len() > 0 && !maValid {
		return ReasonEAPWithoutMA
	}
	if in.RequireMessageAuthenticator && !maValid {
		return ReasonMissingMA
	}
	if in.LimitProxyState && in.Packet.Attributes.AllOf(attribute.TypeProxyState).Len() > 0 && !maValid {
		return ReasonProxyStateWithoutMA
	}
	return ""
}

// Inbound Accounting-Request validates MA when present. It does not apply
// Access require_message_authenticator or limit_proxy_state.
func checkAccountingMA(in Request) string {
	mas := in.Packet.Attributes.AllOf(attribute.TypeMessageAuthenticator)
	if mas.Len() == 0 {
		return ""
	}
	if mas.Len() > 1 {
		return ReasonInvalidMA
	}
	declared := declaredPacket(in)
	if len(declared) == 0 {
		return ReasonMalformedHeader
	}
	if err := crypto.ValidateMessageAuthenticator(in.Secret, declared); err != nil {
		return ReasonInvalidMA
	}
	return ""
}

func declaredPacket(in Request) []byte {
	if len(in.Declared) > 0 {
		return in.Declared
	}
	raw, err := codec.Encode(in.Packet)
	if err != nil {
		return nil
	}
	return raw
}
