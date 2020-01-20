package x509svid

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/spiffe/spiffeid"
	"github.com/spiffe/go-spiffe/uri"
)

// GetIDsFromCertificate extracts the SPIFFE ID and Trust Domain ID from the
// URI SAN of the provided certificate. If the certificate has no URI SAN or
// the SPIFFE ID is malformed, it will return an error.
func GetIDsFromCertificate(peer *x509.Certificate) (string, string, error) {
	switch {
	case len(peer.URIs) == 0:
		return "", "", errors.New("peer certificate contains no URI SAN")
	case len(peer.URIs) > 1:
		return "", "", errors.New("peer certificate contains more than one URI SAN")
	}

	id := peer.URIs[0]

	if err := spiffeid.ValidateURI(id, spiffeid.AllowAny()); err != nil {
		return "", "", err
	}

	return id.String(), spiffeid.TrustDomainID(id.Host), nil
}

// MatchID tries to match a SPIFFE ID, given a certificate
func MatchID(ids []string, cert *x509.Certificate) error {
	parsedIDs, err := uri.GetURINamesFromCertificate(cert)
	if err != nil {
		return err
	}

	for _, parsedID := range parsedIDs {
		for _, id := range ids {
			if parsedID == id {
				return nil
			}
		}
	}

	return fmt.Errorf("SPIFFE ID mismatch")
}
