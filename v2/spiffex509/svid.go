package spiffex509

import (
	"crypto"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// SVID represents a SPIFFE X509-SVID
type SVID struct {
	// ID is the SPIFFE ID of the X509-SVID
	ID spiffeid.ID

	// PrivateKey is the private key for the X509-SVID
	PrivateKey crypto.Signer

	// Certificates are the X.509 certificates of the X509-SVID. The leaf
	// certificate is the X509-SVID certificate. Any remaining certificates (
	// if any) chain the X509-SVID certificate back to a X.509 root for the
	// trust domain.
	Certificates []*x509.Certificate
}
