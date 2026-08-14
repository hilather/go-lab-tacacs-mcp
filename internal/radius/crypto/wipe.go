package crypto

// Wipe overwrites b with zeros. Callers must wipe unhidden passwords
// after credential verification.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
