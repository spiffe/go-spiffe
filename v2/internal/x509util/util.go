package x509util

import (
	"crypto/x509"
)

// NewCertPool returns a new CertPool with the given X.509 certificates
func NewCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

// CopyX509Roots copies a slice of X.509 certificates to a new slice.
func CopyX509Roots(x509Roots []*x509.Certificate) []*x509.Certificate {
	copiedX509Roots := make([]*x509.Certificate, len(x509Roots))
	copy(copiedX509Roots, x509Roots)

	return copiedX509Roots
}

// CertsEqual returns true if the slices of X.509 certificates are equal.
func CertsEqual(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}

	for i, cert := range a {
		if !cert.Equal(b[i]) {
			return false
		}
	}

	return true
}
