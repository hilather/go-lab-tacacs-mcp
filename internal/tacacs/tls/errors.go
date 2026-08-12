package tls

import "errors"

var (
	errNoClientCert    = errors.New("client certificate is required")
	errEarlyData       = errors.New("tls early_data is not accepted")
	errNoServerName    = errors.New("sni is required")
	errUnknownSNI      = errors.New("no tls identity matches the server name")
	errRevoked         = errors.New("client certificate is revoked")
	errCRLUnreadable   = errors.New("crl bundle is unreadable")
	errCRLUnverifiable = errors.New("crl bundle could not be verified")
)
