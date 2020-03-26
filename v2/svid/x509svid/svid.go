package x509svid

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/spiffe/go-spiffe/v2/internal/pemutil"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
)

var x509SVIDErr = errs.Class("x509svid")

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
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, x509SVIDErr.New("cannot read certificate file: %w", err)
	}

	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, x509SVIDErr.New("cannot read key file: %w", err)
	}

	return Parse(certBytes, keyBytes)
}

// Parse parses the X509-SVID from PEM blocks containing certificate and key
// bytes. The certificate must be one or more PEM blocks with ASN.1 DER. The
// key must be a PEM block with PKCS#8 ASN.1 DER.
func Parse(certBytes, keyBytes []byte) (*SVID, error) {
	certs := []*x509.Certificate{}
	for {
		if len(certBytes) == 0 {
			break
		}
		cert, rest, err := pemutil.ParseCertificate(certBytes)
		certBytes = rest
		if errors.Is(err, pemutil.ErrUnexpectedBlockType) {
			continue
		}
		if err != nil {
			return nil, x509SVIDErr.New("cannot parse PEM encoded certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	var privateKey crypto.PrivateKey
	var err error
	for {
		if len(keyBytes) == 0 {
			break
		}
		privateKey, keyBytes, err = pemutil.ParsePrivateKey(keyBytes)
		if errors.Is(err, pemutil.ErrUnexpectedBlockType) {
			continue
		}
		if err != nil {
			return nil, x509SVIDErr.New("cannot parse PEM encoded private key: %v", err)
		}
		break
	}

	return newSVID(certs, privateKey)
}

// ParseRaw parses the X509-SVID from certificate and key bytes. The
// certificate must be ASN.1 DER (concatenated with no intermediate
// padding if there are more than one certificate). The key must be a PKCS#8
// ASN.1 DER.
func ParseRaw(certBytes, keyBytes []byte) (*SVID, error) {
	certificates, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, x509SVIDErr.New("cannot parse DER encoded certificate: %v", err)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, x509SVIDErr.New("cannot parse DER encoded private key: %v", err)
	}

	return newSVID(certificates, privateKey)
}

// Marshal marshals the X509-SVID and returns PEM encoded blocks for the SVID
// and private key.
func (s *SVID) Marshal() ([]byte, []byte, error) {
	certBytes := pemutil.EncodeCertificates(s.Certificates)
	keyBytes, err := pemutil.EncodePKCS8PrivateKey(s.PrivateKey)
	if err != nil {
		return nil, nil, x509SVIDErr.New("cannot encode private key: %v", err)
	}

	return certBytes, keyBytes, nil
}

// MarshalRaw marshals the X509-SVID and returns ASN.1 DER for the certificates
// (concatenated with no intermediate padding) and PKCS8 ASN1.DER for the
// private key.
func (s *SVID) MarshalRaw() ([]byte, []byte, error) {
	key, err := x509.MarshalPKCS8PrivateKey(s.PrivateKey)
	if err != nil {
		return nil, nil, x509SVIDErr.New("cannot marshal private key: %v", err)
	}

	certBytes := []byte{}
	for _, cert := range s.Certificates {
		certBytes = append(certBytes, cert.Raw...)
	}

	return certBytes, key, nil
}

// GetX509SVID returns the X509-SVID. It implements the Source interface.
func (s *SVID) GetX509SVID() (*SVID, error) {
	return s, nil
}

func newSVID(certificates []*x509.Certificate, privateKey interface{}) (*SVID, error) {
	if len(certificates) == 0 {
		return nil, x509SVIDErr.New("no certificates found")
	}

	spiffeID, err := getSPIFFEID(certificates[0])
	if err != nil {
		return nil, x509SVIDErr.New("cannot get SPIFFE ID: %v", err)
	}

	if privateKey == nil {
		return nil, x509SVIDErr.New("no private key found")
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, x509SVIDErr.New("expected crypto.Signer; got %T", privateKey)
	}

	return &SVID{
		Certificates: certificates,
		PrivateKey:   signer,
		ID:           spiffeID,
	}, nil
}

func getSPIFFEID(cert *x509.Certificate) (spiffeid.ID, error) {
	if len(cert.URIs) == 0 {
		return spiffeid.ID{}, errors.New("certificate does not contain URIs")
	}

	id, err := spiffeid.FromURI(cert.URIs[0])
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("unable to parse ID: %v", err)
	}

	return id, nil
}
