package domain

import (
	"errors"
	"fmt"
)

// Code is a stable machine-readable error code shared by REST, MCP, events, and logs.
type Code string

// Adapter-facing codes shared by REST, MCP, and events.
const (
	CodeInvalidArgument  Code = "invalid_argument"
	CodeNotFound         Code = "not_found"
	CodeAlreadyExists    Code = "already_exists"
	CodeConflict         Code = "conflict"
	CodeRevisionMismatch Code = "revision_mismatch"
	CodeUnauthenticated  Code = "unauthenticated"
	CodePermissionDenied Code = "permission_denied"
	CodeRateLimited      Code = "rate_limited"
	CodeUnavailable      Code = "unavailable"
	CodeInternal         Code = "internal"
)

// Config and snapshot-compile codes.
const (
	CodeClientMatchAmbiguous        Code = "CLIENT_MATCH_AMBIGUOUS"
	CodeAuthMethodCredentialMissing Code = "AUTH_METHOD_CREDENTIAL_MISSING"
	CodeConfigYAMLInvalid           Code = "CONFIG_YAML_INVALID"
	CodeConfigUnknownField          Code = "CONFIG_UNKNOWN_FIELD"
	CodeSecretFileUnreadable        Code = "SECRET_FILE_UNREADABLE"
	CodeSharedSecretPolicyViolation Code = "SHARED_SECRET_POLICY_VIOLATION"
	CodeSharedSecretRotationOverdue Code = "SHARED_SECRET_ROTATION_OVERDUE"
	CodeGroupNotFound               Code = "GROUP_NOT_FOUND"
	CodeTLSVersionUnsupported       Code = "TLS_VERSION_UNSUPPORTED"
	CodeObjectLimitExceeded         Code = "OBJECT_LIMIT_EXCEEDED"
	CodeRegexInvalid                Code = "REGEX_INVALID"
	CodeRevisionConflict            Code = "REVISION_CONFLICT"
)

func (c Code) String() string { return string(c) }

// Error is the shared domain error. Adapters map Code without changing meaning.
// Error text must not include secret material.
type Error struct {
	Code    Code
	Message string
	Path    string
	Details map[string]any
}

// NewError returns an error with the given code and operator-safe message.
func NewError(code Code, message string) Error {
	return Error{Code: code, Message: message}
}

// WithPath returns a copy with Path set.
func (e Error) WithPath(path string) Error {
	e.Path = path
	return e
}

// WithDetail returns a copy with one extra detail entry. The previous Details
// map is copied so callers can treat Error values as immutable.
func (e Error) WithDetail(key string, value any) Error {
	n := 1
	if e.Details != nil {
		n = len(e.Details) + 1
	}
	next := make(map[string]any, n)
	for k, v := range e.Details {
		next[k] = v
	}
	next[key] = value
	e.Details = next
	return e
}

func (e Error) Error() string {
	switch {
	case e.Path != "" && e.Message != "":
		return fmt.Sprintf("%s at %s: %s", e.Code, e.Path, e.Message)
	case e.Path != "":
		return fmt.Sprintf("%s at %s", e.Code, e.Path)
	case e.Message != "":
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	default:
		return string(e.Code)
	}
}

// Is reports whether target is an Error with the same Code.
func (e Error) Is(target error) bool {
	switch t := target.(type) {
	case Error:
		return e.Code == t.Code
	case *Error:
		return t != nil && e.Code == t.Code
	default:
		return false
	}
}

// AsError extracts a domain Error from err.
func AsError(err error) (Error, bool) {
	var e Error
	if errors.As(err, &e) {
		return e, true
	}
	var p *Error
	if errors.As(err, &p) && p != nil {
		return *p, true
	}
	return Error{}, false
}
