package attribute

// Built-in IETF MVP attributes plus named Cisco-AVPair (vendor 9 type 1).
func mvpDefinitions() []Definition {
	return []Definition{
		define("User-Name", TypeUserName, KindText, CardinalitySingle, SensitivityRestricted,
			maskOf(PacketAccessRequest, PacketAccessAccept, PacketAccessChallenge, PacketAccountingRequest)),
		define("User-Password", TypeUserPassword, KindString, CardinalitySingle, SensitivitySecret,
			maskOf(PacketAccessRequest)).withOctets(16, 128),
		define("CHAP-Password", TypeCHAPPassword, KindString, CardinalitySingle, SensitivitySecret,
			maskOf(PacketAccessRequest)).withOctets(17, 17),
		define("NAS-IP-Address", TypeNASIPAddress, KindIPv4, CardinalitySingle, SensitivityRestricted,
			maskOf(PacketAccessRequest, PacketAccountingRequest)),
		define("NAS-Port", TypeNASPort, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccessRequest, PacketAccountingRequest)),
		define("Service-Type", TypeServiceType, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccessRequest, PacketAccessAccept, PacketAccessChallenge, PacketAccountingRequest)),
		define("Framed-Protocol", TypeFramedProtocol, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccessRequest, PacketAccessAccept, PacketAccountingRequest)),
		define("Framed-IP-Address", TypeFramedIPAddress, KindIPv4, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccessRequest, PacketAccessAccept, PacketAccountingRequest)),
		define("Filter-Id", TypeFilterID, KindText, CardinalityMulti, SensitivityPublic,
			maskOf(PacketAccessAccept)),
		define("Framed-MTU", TypeFramedMTU, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccessRequest, PacketAccessAccept, PacketAccessChallenge)),
		define("Reply-Message", TypeReplyMessage, KindText, CardinalityMulti, SensitivityPublic,
			maskOf(PacketAccessAccept, PacketAccessReject, PacketAccessChallenge)),
		// State is reserved; the dictionary knows it so role checks can
		// reject illegal use. MVP does not emit it.
		define("State", TypeState, KindString, CardinalitySingle, SensitivitySecret,
			maskOf(PacketAccessRequest, PacketAccessAccept, PacketAccessChallenge)),
		define("Class", TypeClass, KindString, CardinalityMulti, SensitivityRestricted,
			maskOf(PacketAccessAccept, PacketAccountingRequest)),
		define("Vendor-Specific", TypeVendorSpecific, KindVSA, CardinalityMulti, SensitivityRestricted,
			maskOf(PacketAccessRequest, PacketAccessAccept, PacketAccessChallenge, PacketAccountingRequest)),
		define("Session-Timeout", TypeSessionTimeout, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccessAccept, PacketAccessChallenge)),
		define("Idle-Timeout", TypeIdleTimeout, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccessAccept, PacketAccessChallenge)),
		define("Called-Station-Id", TypeCalledStationID, KindText, CardinalitySingle, SensitivityRestricted,
			maskOf(PacketAccessRequest, PacketAccountingRequest)),
		define("Calling-Station-Id", TypeCallingStationID, KindText, CardinalitySingle, SensitivityRestricted,
			maskOf(PacketAccessRequest, PacketAccountingRequest)),
		define("NAS-Identifier", TypeNASIdentifier, KindText, CardinalitySingle, SensitivityRestricted,
			maskOf(PacketAccessRequest, PacketAccountingRequest)),
		define("Proxy-State", TypeProxyState, KindString, CardinalityMulti, SensitivityPublic,
			maskOf(PacketAccessRequest, PacketAccessAccept, PacketAccessReject, PacketAccessChallenge, PacketAccountingRequest, PacketAccountingResponse)),
		define("Acct-Status-Type", TypeAcctStatusType, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccountingRequest)).require(PacketAccountingRequest),
		define("Acct-Delay-Time", TypeAcctDelayTime, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccountingRequest)),
		define("Acct-Input-Octets", TypeAcctInputOctets, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccountingRequest)),
		define("Acct-Output-Octets", TypeAcctOutputOctets, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccountingRequest)),
		define("Acct-Session-Id", TypeAcctSessionID, KindText, CardinalitySingle, SensitivityRestricted,
			maskOf(PacketAccountingRequest)),
		define("Acct-Authentic", TypeAcctAuthentic, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccountingRequest)),
		define("Acct-Session-Time", TypeAcctSessionTime, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccountingRequest)),
		define("Acct-Input-Packets", TypeAcctInputPackets, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccountingRequest)),
		define("Acct-Output-Packets", TypeAcctOutputPackets, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccountingRequest)),
		define("Acct-Terminate-Cause", TypeAcctTerminateCause, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccountingRequest)),
		define("Acct-Input-Gigawords", TypeAcctInputGigawords, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccountingRequest)),
		define("Acct-Output-Gigawords", TypeAcctOutputGigawords, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccountingRequest)),
		define("Event-Timestamp", TypeEventTimestamp, KindTime, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccessRequest, PacketAccessAccept, PacketAccountingRequest)),
		define("CHAP-Challenge", TypeCHAPChallenge, KindString, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccessRequest)),
		define("NAS-Port-Type", TypeNASPortType, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccessRequest, PacketAccountingRequest)),
		// MA is allowed on Accounting-Request (validate-if-present) and
		// required first on every Access and Accounting response.
		define("Message-Authenticator", TypeMessageAuthenticator, KindString, CardinalitySingle, SensitivitySecret,
			maskOf(PacketAccessRequest, PacketAccessAccept, PacketAccessReject, PacketAccessChallenge, PacketAccountingRequest, PacketAccountingResponse)).
			withOctets(16, 16).
			require(PacketAccessAccept, PacketAccessReject, PacketAccessChallenge, PacketAccountingResponse).
			firstIn(PacketAccessAccept, PacketAccessReject, PacketAccessChallenge, PacketAccountingResponse),
		define("Acct-Interim-Interval", TypeAcctInterimInterval, KindInteger, CardinalitySingle, SensitivityPublic,
			maskOf(PacketAccessAccept)),
		define("NAS-IPv6-Address", TypeNASIPv6Address, KindIPv6, CardinalitySingle, SensitivityRestricted,
			maskOf(PacketAccessRequest, PacketAccountingRequest)),
		// RFC 2548 Microsoft VSAs (vendor 311). Named, not operator-dict.
		defineVendor("MS-CHAP-Response", VendorMicrosoft, VendorTypeMSCHAPResponse, KindString, CardinalitySingle, SensitivitySecret,
			maskOf(PacketAccessRequest)).withOctets(MSCHAPResponseWireLen, MSCHAPResponseWireLen),
		defineVendor("MS-CHAP-Error", VendorMicrosoft, VendorTypeMSCHAPError, KindText, CardinalitySingle, SensitivitySecret,
			maskOf(PacketAccessReject)),
		defineVendor("MS-CHAP-Challenge", VendorMicrosoft, VendorTypeMSCHAPChallenge, KindString, CardinalitySingle, SensitivitySecret,
			maskOf(PacketAccessRequest)).withOctets(MSCHAPChallengeV1Len, MSCHAPChallengeV2Len),
		defineVendor("MS-CHAP2-Response", VendorMicrosoft, VendorTypeMSCHAP2Response, KindString, CardinalitySingle, SensitivitySecret,
			maskOf(PacketAccessRequest)).withOctets(MSCHAPResponseWireLen, MSCHAPResponseWireLen),
		defineVendor("MS-CHAP2-Success", VendorMicrosoft, VendorTypeMSCHAP2Success, KindString, CardinalitySingle, SensitivitySecret,
			maskOf(PacketAccessAccept)).withOctets(MSCHAP2SuccessWireLen, MSCHAP2SuccessWireLen),
		defineVendor(NameCiscoAVPair, VendorCisco, TypeCiscoAVPair, KindText, CardinalityMulti, SensitivityRestricted,
			maskOf(PacketAccessRequest, PacketAccessAccept, PacketAccessReject, PacketAccessChallenge, PacketAccountingRequest)),
	}
}

func defineVendor(name string, vendor uint32, code uint8, kind ValueKind, card Cardinality, sens Sensitivity, allow packetMask) Definition {
	d := define(name, code, kind, card, sens, allow)
	d.Vendor = vendor
	return d
}

func define(name string, code uint8, kind ValueKind, card Cardinality, sens Sensitivity, allow packetMask) Definition {
	d := Definition{
		Name:        name,
		Code:        code,
		Kind:        kind,
		Cardinality: card,
		Sensitivity: sens,
		allowed:     allow,
		MaxOctets:   MaxValueLength,
	}
	switch kind {
	case KindInteger, KindIPv4, KindTime:
		d.MinOctets, d.MaxOctets = 4, 4
	case KindIPv6:
		d.MinOctets, d.MaxOctets = 16, 16
	case KindVSA:
		d.MinOctets = vendorIDSize
	}
	return d
}

func (d Definition) withOctets(min, max int) Definition {
	d.MinOctets = min
	d.MaxOctets = max
	return d
}

func (d Definition) require(codes ...uint8) Definition {
	d.required = maskOf(codes...)
	return d
}

func (d Definition) firstIn(codes ...uint8) Definition {
	d.first = maskOf(codes...)
	return d
}
