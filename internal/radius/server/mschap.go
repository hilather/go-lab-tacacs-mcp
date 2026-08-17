package server

import (
	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
)

const (
	methodMSCHAPv1 = "mschapv1"
	methodMSCHAPv2 = "mschapv2"
)

type mschapEvidence struct {
	v1Resp    []attribute.VendorTLV
	v2Resp    []attribute.VendorTLV
	chal      []attribute.VendorTLV
	malformed bool
}

func collectMSCHAP(attrs attribute.RawSet) mschapEvidence {
	var ev mschapEvidence
	for _, raw := range attrs.AllOf(attribute.TypeVendorSpecific) {
		vsa, err := attribute.ParseVSA(raw)
		if err != nil || vsa.Vendor != attribute.VendorMicrosoft {
			continue
		}
		tlvs, err := attribute.ParseVendorTLVs(vsa.Payload)
		if err != nil {
			ev.malformed = true
			return ev
		}
		for _, t := range tlvs {
			switch t.Type {
			case attribute.VendorTypeMSCHAPChallenge:
				ev.chal = append(ev.chal, t)
			case attribute.VendorTypeMSCHAPResponse:
				ev.v1Resp = append(ev.v1Resp, t)
			case attribute.VendorTypeMSCHAP2Response:
				ev.v2Resp = append(ev.v2Resp, t)
			}
		}
	}
	return ev
}

func (e mschapEvidence) present() bool {
	return len(e.chal) > 0 || len(e.v1Resp) > 0 || len(e.v2Resp) > 0 || e.malformed
}

func extractMSCHAPEvidence(in Request, ms mschapEvidence, wipe func()) (aaa.CredentialEvidence, string, func()) {
	var ev aaa.CredentialEvidence
	if ms.malformed {
		return ev, ReasonConflictingAuth, wipe
	}
	if len(ms.v1Resp) > 1 || len(ms.v2Resp) > 1 || len(ms.chal) > 1 {
		return ev, ReasonConflictingAuth, wipe
	}
	if len(ms.v1Resp) > 0 && len(ms.v2Resp) > 0 {
		return ev, ReasonConflictingAuth, wipe
	}
	if len(ms.v1Resp) == 0 && len(ms.v2Resp) == 0 {
		return ev, ReasonUnsupportedMethod, wipe
	}

	if len(ms.v1Resp) == 1 {
		if !methodAllowed(in.AllowedMethods, methodMSCHAPv1) {
			return ev, ReasonUnsupportedMethod, wipe
		}
		if len(ms.chal) != 1 || len(ms.chal[0].Value) != attribute.MSCHAPChallengeV1Len {
			return ev, ReasonConflictingAuth, wipe
		}
		wire := ms.v1Resp[0].Value
		if len(wire) != attribute.MSCHAPResponseWireLen {
			return ev, ReasonConflictingAuth, wipe
		}
		mapped := mapMSCHAPv1(wire)
		wipe = joinWipe(wipe, func() { credentialsWipe(mapped) })
		return aaa.CredentialEvidence{
			Method:    domain.AuthMethodMSCHAPv1,
			CHAPID:    wire[0],
			Challenge: append([]byte(nil), ms.chal[0].Value...),
			Response:  mapped,
		}, "", wipe
	}

	if !methodAllowed(in.AllowedMethods, methodMSCHAPv2) {
		return ev, ReasonUnsupportedMethod, wipe
	}
	if len(ms.chal) != 1 || len(ms.chal[0].Value) != attribute.MSCHAPChallengeV2Len {
		return ev, ReasonConflictingAuth, wipe
	}
	wire := ms.v2Resp[0].Value
	if len(wire) != attribute.MSCHAPResponseWireLen {
		return ev, ReasonConflictingAuth, wipe
	}
	mapped, ok := mapMSCHAPv2(wire)
	if !ok {
		credentialsWipe(mapped)
		return ev, ReasonConflictingAuth, wipe
	}
	wipe = joinWipe(wipe, func() { credentialsWipe(mapped) })
	return aaa.CredentialEvidence{
		Method:    domain.AuthMethodMSCHAPv2,
		CHAPID:    wire[0],
		Challenge: append([]byte(nil), ms.chal[0].Value...),
		Response:  mapped,
	}, "", wipe
}

// mapMSCHAPv1 is the exact RFC 2548 50→49 layout for VerifyMSCHAPv1.
func mapMSCHAPv1(radius []byte) []byte {
	out := make([]byte, credentials.MSCHAPResponseLen)
	copy(out[0:24], radius[2:26])
	copy(out[24:48], radius[26:50])
	out[48] = radius[1]
	return out
}

// mapMSCHAPv2 is the exact RFC 2548 50→49 layout for VerifyMSCHAPv2.
// Reserved [18:26] of the RADIUS value must be zero.
func mapMSCHAPv2(radius []byte) ([]byte, bool) {
	out := make([]byte, credentials.MSCHAPResponseLen)
	copy(out[0:16], radius[2:18])
	copy(out[16:24], radius[18:26])
	copy(out[24:48], radius[26:50])
	out[48] = 0x00
	for _, b := range out[16:24] {
		if b != 0 {
			return out, false
		}
	}
	return out, true
}

func joinWipe(a, b func()) func() {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func() { a(); b() }
}

func credentialsWipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
