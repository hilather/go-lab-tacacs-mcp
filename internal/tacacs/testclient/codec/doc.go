// Package codec is the independent TACACS+ header and legacy-pad copy
// used only by the test client.
//
// It must not import the server codec (internal/tacacs/codec) or
// tools/spike. Wire behavior is proven against testdata/protocol
// fixtures, not by sharing implementation.
package codec
