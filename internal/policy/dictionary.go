package policy

import (
	"net"
	"strconv"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Encoding is the RFC 8907 value encoding for a known argument.
type Encoding string

const (
	EncText       Encoding = "text"
	EncBoolean    Encoding = "boolean"
	EncNumeric    Encoding = "numeric"
	EncPrivilege  Encoding = "privilege"
	EncAddress    Encoding = "address"
	EncRepeatable Encoding = "repeatable_text"
	EncTimezone   Encoding = "timezone"
	EncEpoch      Encoding = "epoch"
	EncUnknown    Encoding = "unknown"
)

// ArgSpec describes one dictionary entry.
type ArgSpec struct {
	Name       string
	Encoding   Encoding
	Known      bool
	Repeatable bool
}

// RFC 8907 common authorization arguments (T89-AV-001–016) plus encodings
// needed to validate numeric/boolean/address/time values.
var commonArgs = []ArgSpec{
	{Name: "service", Encoding: EncText, Known: true},
	{Name: "protocol", Encoding: EncText, Known: true},
	{Name: "cmd", Encoding: EncText, Known: true},
	{Name: "cmd-arg", Encoding: EncRepeatable, Known: true, Repeatable: true},
	{Name: "acl", Encoding: EncNumeric, Known: true},
	{Name: "inacl", Encoding: EncText, Known: true},
	{Name: "outacl", Encoding: EncText, Known: true},
	{Name: "addr", Encoding: EncAddress, Known: true},
	{Name: "addr-pool", Encoding: EncText, Known: true},
	{Name: "timeout", Encoding: EncNumeric, Known: true},
	{Name: "idletime", Encoding: EncNumeric, Known: true},
	{Name: "autocmd", Encoding: EncText, Known: true},
	{Name: "noescape", Encoding: EncBoolean, Known: true},
	{Name: "nohangup", Encoding: EncBoolean, Known: true},
	{Name: "priv-lvl", Encoding: EncPrivilege, Known: true},
	{Name: "timezone", Encoding: EncTimezone, Known: true},
	{Name: "start_time", Encoding: EncEpoch, Known: true},
	{Name: "stop_time", Encoding: EncEpoch, Known: true},
}

var commonByName map[string]ArgSpec

func init() {
	commonByName = make(map[string]ArgSpec, len(commonArgs))
	for _, s := range commonArgs {
		commonByName[s.Name] = s
	}
}

// LookupArg returns the dictionary spec. Unknown names are vendor attributes.
func LookupArg(name string) ArgSpec {
	if s, ok := commonByName[name]; ok {
		return s
	}
	return ArgSpec{Name: name, Encoding: EncUnknown, Known: false}
}

// KnownArgs returns the RFC common dictionary in declared order.
func KnownArgs() []ArgSpec {
	out := make([]ArgSpec, len(commonArgs))
	copy(out, commonArgs)
	return out
}

// ValidatePair checks wire form and, for known names, value encoding.
// Vendor/unknown names are accepted after wire validation.
func ValidatePair(p domain.AVPair) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return ValidateValue(p.Name, p.Value)
}

// ValidateValue checks a known argument's encoding. Empty text is allowed.
func ValidateValue(name, value string) error {
	spec := LookupArg(name)
	if !spec.Known {
		return nil
	}
	switch spec.Encoding {
	case EncText, EncRepeatable:
		return nil
	case EncBoolean:
		if value != "true" && value != "false" {
			return domain.NewError(domain.CodeInvalidArgument, "boolean argument must be true or false").WithPath(name)
		}
	case EncNumeric:
		if _, err := parseBoundedUint(value); err != nil {
			return domain.NewError(domain.CodeInvalidArgument, "numeric argument is unrepresentable").WithPath(name)
		}
	case EncPrivilege:
		n, err := parseBoundedUint(value)
		if err != nil || n > uint64(domain.PrivilegeMax) {
			return domain.NewError(domain.CodeInvalidArgument, "privilege level must be 0-15").WithPath(name)
		}
	case EncAddress:
		if net.ParseIP(value) == nil {
			return domain.NewError(domain.CodeInvalidArgument, "address must be canonical IPv4 or IPv6 text").WithPath(name)
		}
	case EncTimezone:
		if err := validateTimezone(value); err != nil {
			return err
		}
	case EncEpoch:
		if _, err := parseBoundedUint(value); err != nil {
			return domain.NewError(domain.CodeInvalidArgument, "epoch seconds are unrepresentable").WithPath(name)
		}
	}
	return nil
}

// ParseEpochSeconds interprets value as UTC Unix seconds unless loc is set.
func ParseEpochSeconds(value string, loc *time.Location) (time.Time, error) {
	n, err := parseBoundedUint(value)
	if err != nil {
		return time.Time{}, domain.NewError(domain.CodeInvalidArgument, "epoch seconds are unrepresentable")
	}
	if loc == nil {
		loc = time.UTC
	}
	return time.Unix(int64(n), 0).In(loc), nil
}

// LoadLocation returns UTC for empty/"UTC"/"Z", a fixed offset, or an IANA name.
func LoadLocation(timezone string) (*time.Location, error) {
	if timezone == "" || timezone == "UTC" || timezone == "Z" {
		return time.UTC, nil
	}
	if loc, err := time.LoadLocation(timezone); err == nil {
		return loc, nil
	}
	if loc, err := parseFixedOffset(timezone); err == nil {
		return loc, nil
	}
	return nil, domain.NewError(domain.CodeInvalidArgument, "unknown timezone").WithPath("timezone")
}

func validateTimezone(value string) error {
	_, err := LoadLocation(value)
	return err
}

func parseFixedOffset(s string) (*time.Location, error) {
	if len(s) < 2 || (s[0] != '+' && s[0] != '-') {
		return nil, domain.NewError(domain.CodeInvalidArgument, "unknown timezone")
	}
	sign := 1
	if s[0] == '-' {
		sign = -1
	}
	rest := s[1:]
	var hours, mins int
	var err error
	switch {
	case len(rest) == 2:
		hours, err = strconv.Atoi(rest)
	case len(rest) == 4:
		hours, err = strconv.Atoi(rest[:2])
		if err == nil {
			mins, err = strconv.Atoi(rest[2:])
		}
	case len(rest) == 5 && rest[2] == ':':
		hours, err = strconv.Atoi(rest[:2])
		if err == nil {
			mins, err = strconv.Atoi(rest[3:])
		}
	default:
		return nil, domain.NewError(domain.CodeInvalidArgument, "unknown timezone")
	}
	if err != nil || hours > 14 || mins > 59 {
		return nil, domain.NewError(domain.CodeInvalidArgument, "unknown timezone")
	}
	return time.FixedZone(s, sign*(hours*3600+mins*60)), nil
}

// Max decimal digits that can fit in uint64.
const maxUintDigits = 20

func parseBoundedUint(s string) (uint64, error) {
	if s == "" || len(s) > maxUintDigits {
		return 0, domain.NewError(domain.CodeInvalidArgument, "numeric argument is unrepresentable")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, domain.NewError(domain.CodeInvalidArgument, "numeric argument is unrepresentable")
		}
	}
	if len(s) == maxUintDigits && s > "18446744073709551615" {
		return 0, domain.NewError(domain.CodeInvalidArgument, "numeric argument is unrepresentable")
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, domain.NewError(domain.CodeInvalidArgument, "numeric argument is unrepresentable")
	}
	return n, nil
}

func firstAV(args domain.AVPairs, name string) (string, bool) {
	for _, p := range args {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

func allAV(args domain.AVPairs, name string) []string {
	var out []string
	for _, p := range args {
		if p.Name == name {
			out = append(out, p.Value)
		}
	}
	return out
}

func extractFromAVs(args domain.AVPairs) (service, protocol, cmd string, cmdPresent bool, cmdArgs []string) {
	service, _ = firstAV(args, "service")
	protocol, _ = firstAV(args, "protocol")
	cmd, cmdPresent = firstAV(args, "cmd")
	cmdArgs = allAV(args, "cmd-arg")
	return service, protocol, cmd, cmdPresent, cmdArgs
}
