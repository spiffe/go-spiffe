package x509svid

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// VerifyChain verifies an X509-SVID chain using the X.509 bundle source. It
// returns the SPIFFE ID of the X509-SVID and one or more chains back to a root
// in the bundle.
func Verify(certs []*x509.Certificate, bundleSource x509bundle.Source) (spiffeid.ID, [][]*x509.Certificate, error) {
	panic("not implemented")
}

// ParseAndVerifyChain parses and verifies an X509-SVID chain using the X.509
// bundle source. It returns the SPIFFE ID of the X509-SVID and one or more
// chains back to a root in the bundle.
func ParseAndVerify(certs [][]byte, bundleSource x509bundle.Source) (spiffeid.ID, [][]*x509.Certificate, error) {
	panic("not implemented")
}
