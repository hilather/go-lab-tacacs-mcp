package testclient

import "errors"

var (
	// ErrMissingUnencrypted is returned when a TLS peer omits
	// TAC_PLUS_UNENCRYPTED_FLAG. The connection is closed.
	ErrMissingUnencrypted = errors.New("tls tacacs reply missing TAC_PLUS_UNENCRYPTED_FLAG")

	// ErrIdentityMismatch is returned when the server certificate does
	// not match the configured DNS-ID, IP-ID, or SRV-ID.
	ErrIdentityMismatch = errors.New("tls server identity mismatch")

	// ErrNoServerCertificate is returned when the handshake yields no leaf.
	ErrNoServerCertificate = errors.New("tls server certificate is missing")

	// ErrURIIDNotUsed is returned if a caller asks to validate URI-ID.
	// RFC 9887 §3.4.2 does not use URI-ID for TACACS+ server identity.
	ErrURIIDNotUsed = errors.New("uri-id is not used for tacacs server identity")
)
