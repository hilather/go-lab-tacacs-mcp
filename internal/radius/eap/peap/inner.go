package peap

import (
	"encoding/binary"
	"errors"
)

// Inner EAP types used after the PEAP TLS tunnel is up.
const (
	InnerIdentity = 1
	InnerMSCHAPv2 = 26

	innerCodeRequest  = 1
	innerCodeResponse = 2
	innerCodeSuccess  = 3
	innerCodeFailure  = 4

	MSCHAPOpChallenge = 1
	MSCHAPOpResponse  = 2
	MSCHAPOpSuccess   = 3
	MSCHAPOpFailure   = 4
)

// InnerPacket is one EAP packet carried as TLS application data.
type InnerPacket struct {
	Code       byte
	Identifier byte
	Type       byte
	Data       []byte
	HasType    bool
}

// EncodeInner writes a full EAP packet.
func EncodeInner(p InnerPacket) []byte {
	if p.Code == innerCodeSuccess || p.Code == innerCodeFailure {
		return []byte{p.Code, p.Identifier, 0, 4}
	}
	n := 5 + len(p.Data)
	out := make([]byte, n)
	out[0] = p.Code
	out[1] = p.Identifier
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	out[4] = p.Type
	copy(out[5:], p.Data)
	return out
}

// DecodeInner parses one inner EAP packet. Length must match the buffer.
func DecodeInner(b []byte) (InnerPacket, error) {
	if len(b) < 4 {
		return InnerPacket{}, errors.New("peap: short inner EAP")
	}
	n := int(b[2])<<8 | int(b[3])
	if n != len(b) || n < 4 {
		return InnerPacket{}, errors.New("peap: inner EAP length")
	}
	p := InnerPacket{Code: b[0], Identifier: b[1]}
	switch p.Code {
	case innerCodeSuccess, innerCodeFailure:
		if n != 4 {
			return InnerPacket{}, errors.New("peap: inner success/failure length")
		}
		return p, nil
	case innerCodeRequest, innerCodeResponse:
		if n < 5 {
			return InnerPacket{}, errors.New("peap: inner typed length")
		}
		p.HasType = true
		p.Type = b[4]
		if n > 5 {
			p.Data = append([]byte(nil), b[5:]...)
		}
		return p, nil
	default:
		return InnerPacket{}, errors.New("peap: inner EAP code")
	}
}

// IdentityRequest is inner EAP-Request/Identity.
func IdentityRequest(id byte) []byte {
	return EncodeInner(InnerPacket{Code: innerCodeRequest, Identifier: id, Type: InnerIdentity, HasType: true})
}

// InnerSuccess is inner EAP-Success.
func InnerSuccess(id byte) []byte {
	return EncodeInner(InnerPacket{Code: innerCodeSuccess, Identifier: id})
}

// InnerFailure is inner EAP-Failure.
func InnerFailure(id byte) []byte {
	return EncodeInner(InnerPacket{Code: innerCodeFailure, Identifier: id})
}

// EncodeMSCHAPChallenge is EAP-Request/EAP-MSCHAPv2 Challenge (RFC 2759).
func EncodeMSCHAPChallenge(eapID, msID byte, challenge []byte, name string) []byte {
	if len(challenge) != 16 {
		challenge = append(challenge, make([]byte, 16-len(challenge))...)
		if len(challenge) > 16 {
			challenge = challenge[:16]
		}
	}
	msLen := 21 + len(name)
	data := make([]byte, msLen)
	data[0] = MSCHAPOpChallenge
	data[1] = msID
	binary.BigEndian.PutUint16(data[2:4], uint16(msLen))
	data[4] = 16
	copy(data[5:21], challenge)
	copy(data[21:], name)
	return EncodeInner(InnerPacket{Code: innerCodeRequest, Identifier: eapID, Type: InnerMSCHAPv2, HasType: true, Data: data})
}

// EncodeMSCHAPSuccess is EAP-Request/EAP-MSCHAPv2 Success. message is
// typically "S=" plus 40 hex from credentials.GenerateMSCHAPv2Success[1:].
func EncodeMSCHAPSuccess(eapID, msID byte, message []byte) []byte {
	msLen := 4 + len(message)
	data := make([]byte, msLen)
	data[0] = MSCHAPOpSuccess
	data[1] = msID
	binary.BigEndian.PutUint16(data[2:4], uint16(msLen))
	copy(data[4:], message)
	return EncodeInner(InnerPacket{Code: innerCodeRequest, Identifier: eapID, Type: InnerMSCHAPv2, HasType: true, Data: data})
}

// ParseMSCHAPResponse extracts the 49-octet RFC 2759 response from an
// inner EAP-Response/EAP-MSCHAPv2.
func ParseMSCHAPResponse(p InnerPacket) (msID byte, response []byte, name string, ok bool) {
	if p.Code != innerCodeResponse || p.Type != InnerMSCHAPv2 || len(p.Data) < 54 {
		return 0, nil, "", false
	}
	if p.Data[0] != MSCHAPOpResponse || p.Data[4] != 49 {
		return 0, nil, "", false
	}
	msID = p.Data[1]
	response = append([]byte(nil), p.Data[5:54]...)
	if len(p.Data) > 54 {
		name = string(p.Data[54:])
	}
	return msID, response, name, true
}

// MaxTLSPerMessage is the TLS-data budget inside one concatenated EAP-Message.
const MaxTLSPerMessage = 1000

// EncodeFlight splits TLS records into PEAPv0 bodies (L/M as needed).
func EncodeFlight(tlsData []byte) [][]byte {
	if len(tlsData) == 0 {
		return [][]byte{Encode(Payload{Version: Version0})}
	}
	if len(tlsData) <= MaxTLSPerMessage {
		return [][]byte{Encode(Payload{Version: Version0, TLSData: tlsData})}
	}
	var out [][]byte
	rest := tlsData
	first := true
	for len(rest) > 0 {
		n := len(rest)
		if n > MaxTLSPerMessage {
			n = MaxTLSPerMessage
		}
		p := Payload{Version: Version0, TLSData: rest[:n]}
		if first {
			p.LengthIncluded = true
			p.TLSMessageLen = uint32(len(tlsData))
			first = false
		}
		if n < len(rest) {
			p.MoreFragments = true
		}
		out = append(out, Encode(p))
		rest = rest[n:]
	}
	return out
}
