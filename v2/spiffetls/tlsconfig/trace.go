package tlsconfig

import (
	"crypto/tls"
)

// GetCertificateInfo contains trace information when using an X.509 source to
// obtain a certificate for the TLS handshake.
type GetCertificateInfo struct {
}

// GotCertificateInfo contains trace information after using an X.509 source to
// obtain a certificate for the TLS handshake.
type GotCertificateInfo struct {
	Cert *tls.Certificate
	Err  error
}

// Trace is the interface to define what functions are triggered when functions
// in tlsconfig are called
type Trace struct {
	GetCertificate func(GetCertificateInfo) interface{}
	GotCertificate func(GotCertificateInfo, interface{})
}
