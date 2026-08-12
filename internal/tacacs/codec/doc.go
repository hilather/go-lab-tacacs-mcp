// Package codec encodes and decodes TACACS+ headers and packet bodies.
//
// It does not perform network I/O. Callers must allocate bodies with
// AllocateBody or DecodePacket so a huge header Length cannot force an
// unbounded allocation. Sequence and single-connect helpers are
// connection-state machines, not a listener.
//
// This package must not be imported by the independent test client
// codec (internal/tacacs/testclient/codec).
package codec
