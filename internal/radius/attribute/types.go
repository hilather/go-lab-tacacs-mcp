package attribute

// IETF attribute type numbers for the built-in MVP dictionary (RAD-CODEC-004).
// Named Cisco-AVPair is not in this table.
const (
	TypeUserName             uint8 = 1
	TypeUserPassword         uint8 = 2
	TypeCHAPPassword         uint8 = 3
	TypeNASIPAddress         uint8 = 4
	TypeNASPort              uint8 = 5
	TypeServiceType          uint8 = 6
	TypeFramedProtocol       uint8 = 7
	TypeFramedIPAddress      uint8 = 8
	TypeFilterID             uint8 = 11
	TypeFramedMTU            uint8 = 12
	TypeReplyMessage         uint8 = 18
	TypeState                uint8 = 24
	TypeClass                uint8 = 25
	TypeVendorSpecific       uint8 = 26
	TypeSessionTimeout       uint8 = 27
	TypeIdleTimeout          uint8 = 28
	TypeCalledStationID      uint8 = 30
	TypeCallingStationID     uint8 = 31
	TypeNASIdentifier        uint8 = 32
	TypeProxyState           uint8 = 33
	TypeAcctStatusType       uint8 = 40
	TypeAcctDelayTime        uint8 = 41
	TypeAcctInputOctets      uint8 = 42
	TypeAcctOutputOctets     uint8 = 43
	TypeAcctSessionID        uint8 = 44
	TypeAcctAuthentic        uint8 = 45
	TypeAcctSessionTime      uint8 = 46
	TypeAcctInputPackets     uint8 = 47
	TypeAcctOutputPackets    uint8 = 48
	TypeAcctTerminateCause   uint8 = 49
	TypeAcctInputGigawords   uint8 = 52
	TypeAcctOutputGigawords  uint8 = 53
	TypeEventTimestamp       uint8 = 55
	TypeCHAPChallenge        uint8 = 60
	TypeNASPortType          uint8 = 61
	TypeMessageAuthenticator uint8 = 80
	TypeAcctInterimInterval  uint8 = 85
	TypeNASIPv6Address       uint8 = 95
)

// MaxValueLength is the maximum Value size (Length is one octet and includes Type+Length).
const MaxValueLength = 253

// DefaultMaxAttributes is the default decoded attribute count cap.
const DefaultMaxAttributes = 256

// DefaultMaxValueBytes is the default sum of attribute Value bytes.
const DefaultMaxValueBytes = 4096
