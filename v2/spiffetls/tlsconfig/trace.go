package tlsconfig

import (
	"crypto/tls"
)

// GotCertificateInfo provides err and TLS certificate info to Trace
type GotCertificateInfo struct {
	Cert *tls.Certificate
	Err  error
}

// Trace is the interface to define what functions are triggered when functions
// in tlsconfig are called
type Trace struct {
	GetCertificate func() interface{}
	GotCertificate func(interface{}, GotCertificateInfo)
}
