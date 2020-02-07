package spiffex509

import (
	"crypto"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// SVID represents a SPIFFE X509-SVID
type SVID struct {
	ID           spiffeid.ID
	PrivateKey   crypto.Signer
	Certificates []*x509.Certificate
}
