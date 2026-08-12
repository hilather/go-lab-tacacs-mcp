package server

import "errors"

var (
	// ErrUnencrypted is returned by a legacy PacketIO when the client set
	// TAC_PLUS_UNENCRYPTED_FLAG. The connection must ERROR and drain.
	ErrUnencrypted = errors.New("legacy packet has unencrypted flag set")

	// ErrSecretMismatch is a length-sum failure after deobfuscation.
	// The connection must ERROR, accept no new sessions, and drain.
	ErrSecretMismatch = errors.New("legacy body lengths do not match after deobfuscation")

	// ErrConnLimit is returned when the listener connection cap is reached.
	ErrConnLimit = errors.New("connection limit reached")
)
