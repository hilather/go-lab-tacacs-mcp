// Package tls binds the RFC 9887 secure TACACS+ TLS 1.3 listener.
//
// The socket begins TLS immediately after Accept. There is no preface,
// STARTTLS, protocol sniffing, or fallback to the legacy listener.
// Packet bodies are TLS application data; RFC 8907 obfuscation is never
// applied. Every TACACS header must have TAC_PLUS_UNENCRYPTED_FLAG set.
package tls
