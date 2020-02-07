package x509svid

import (
	"crypto"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// SVID represents a SPIFFE X509-SVID.
type SVID struct {
	// ID is the SPIFFE ID of the X509-SVID.
	ID spiffeid.ID

	// Certificates are the X.509 certificates of the X509-SVID. The leaf
	// certificate is the X509-SVID certificate. Any remaining certificates (
	// if any) chain the X509-SVID certificate back to a X.509 root for the
	// trust domain.
	Certificates []*x509.Certificate

	// PrivateKey is the private key for the X509-SVID.
	PrivateKey crypto.Signer
}

// Load loads the X509-SVID from PEM encoded files on disk. certFile and
// keyFile may be the same file.
func Load(certFile, keyFile string) (*SVID, error) {
	panic("not implemented")
}

// Parse parses the X509-SVID from PEM blocks containing certificate and key
// bytes. The certificate must be one or more PEM blocks with ASN.1 DER. The
// key must be a PEM block with PKCS#8 ASN.1 DER.
func Parse(certBytes, keyBytes []byte) (*SVID, error) {
	panic("not implemented")
}

// ParseRaw parses the X509-SVID from certificate and key bytes. The
// certificate must be ASN.1 DER (concatenated with no intermediate
// padding if there are more than one certificate). The key must be a PKCS#8
// ASN.1 DER.
func ParseRaw(certBytes, keyBytes []byte) (*SVID, error) {
	panic("not implemented")
}

// Marshal marshals the X509-SVID and returns PEM encoded blocks for the SVID
// and private key.
func (s *SVID) Marshal() ([]byte, []byte, error) {
	panic("not implemented")
}

// MarshalRaw marshals the X509-SVID and returns ASN.1 DER for the certificates
// (concatenated with no intermediate padding) and PKCS8 ASN1.DER for the
// private key.
func (s *SVID) MarshalRaw() ([]byte, []byte, error) {
	panic("not implemented")
}

// GetX509SVID returns the X509-SVID. It implements the Source interface.
func (s *SVID) GetX509SVID() (*SVID, error) {
	return s, nil
}
