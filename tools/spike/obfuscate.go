package spike

import (
	"crypto/md5"
	"encoding/binary"
)

// Obfuscate applies RFC 8907 §4.5 packet-body obfuscation (XOR with the MD5 pad).
// The transform is involutive: Obfuscate(Obfuscate(body)) == body.
// sessionID is the header field in network byte order, as on the wire.
func Obfuscate(sessionID uint32, version, seqNo byte, key, body []byte) []byte {
	if len(body) == 0 {
		return []byte{}
	}
	out := make([]byte, len(body))
	pad := obfuscationPad(sessionID, version, seqNo, key, len(body))
	for i := range body {
		out[i] = body[i] ^ pad[i]
	}
	return out
}

func obfuscationPad(sessionID uint32, version, seqNo byte, key []byte, n int) []byte {
	sid := make([]byte, 4)
	binary.BigEndian.PutUint32(sid, sessionID)

	prefix := make([]byte, 0, 4+len(key)+2)
	prefix = append(prefix, sid...)
	prefix = append(prefix, key...)
	prefix = append(prefix, version, seqNo)

	pad := make([]byte, 0, n+md5.Size)
	var prev []byte
	for len(pad) < n {
		h := md5.New()
		_, _ = h.Write(prefix)
		_, _ = h.Write(prev)
		prev = h.Sum(nil)
		pad = append(pad, prev...)
	}
	return pad[:n]
}
