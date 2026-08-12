// Package codec encodes and decodes TACACS+ packet headers and the
// RFC 8907 §4.5 legacy body pad.
//
// It does not perform network I/O. Body families (START/CONTINUE/REPLY
// and author/acct payloads) are not implemented here. Callers must
// allocate bodies with AllocateBody or DecodePacket so a huge header
// Length cannot force an unbounded allocation.
//
// This package must not be imported by the independent test client
// codec (internal/tacacs/testclient/codec).
package codec
