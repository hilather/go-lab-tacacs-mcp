package attribute

// Sensitivity classifies whether an attribute value may appear in logs,
// events, or admin surfaces. Unknown types are SensitivityUnknown.
type Sensitivity string

const (
	SensitivitySecret     Sensitivity = "secret"
	SensitivityRestricted Sensitivity = "restricted"
	SensitivityPublic     Sensitivity = "public"
	SensitivityUnknown    Sensitivity = "unknown"
)

// Sensitive reports types whose values must never appear in logs or errors.
func Sensitive(typ uint8) bool {
	return Builtin().SensitivityOf(typ) == SensitivitySecret
}

// Restricted reports types that events may summarize but not label metrics with.
func Restricted(typ uint8) bool {
	return Builtin().SensitivityOf(typ) == SensitivityRestricted
}

// SensitivityOf is the built-in classification for an IETF type octet.
func (d Dictionary) SensitivityOf(typ uint8) Sensitivity {
	if def, ok := d.LookupIETF(typ); ok {
		return def.Sensitivity
	}
	return SensitivityUnknown
}
