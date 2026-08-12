package server

import "errors"

var (
	// ErrUnencrypted is returned by a legacy PacketIO when the client set
	// TAC_PLUS_UNENCRYPTED_FLAG. The connection must ERROR and drain.
	ErrUnencrypted = errors.New("legacy packet has unencrypted flag set")

	// ErrMissingUnencrypted is returned by a TLS PacketIO when the client
	// omitted TAC_PLUS_UNENCRYPTED_FLAG. The connection must send a
	// type-specific ERROR with the flag set and terminate.
	ErrMissingUnencrypted = errors.New("tls packet missing unencrypted flag")

	// ErrSecretMismatch is a length-sum failure after deobfuscation.
	// The connection must ERROR, accept no new sessions, and drain.
	ErrSecretMismatch = errors.New("legacy body lengths do not match after deobfuscation")

	// ErrConnLimit is returned when the listener connection cap is reached.
	ErrConnLimit = errors.New("connection limit reached")
)
