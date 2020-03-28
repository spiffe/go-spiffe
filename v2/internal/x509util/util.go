package x509util

import (
	"bytes"
	"crypto/x509"
)

func NewCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

// CertsEqual checks if two X.509 certificates are equal by comparing its raw bytes
func CertsEqual(a, b *x509.Certificate) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	return bytes.Equal(a.Raw, b.Raw)
}
