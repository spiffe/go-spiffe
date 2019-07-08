package internal

import (
	"crypto/x509"
	"errors"
	"net/url"
)

func GetIDsFromCertificate(peer *x509.Certificate) (string, string, error) {
	switch {
	case len(peer.URIs) == 0:
		return "", "", errors.New("peer certificate contains no URI SAN")
	case len(peer.URIs) > 1:
		return "", "", errors.New("peer certificate contains more than one URI SAN")
	}

	uriSAN := peer.URIs[0]
	if uriSAN.Scheme != "spiffe" {
		return "", "", errors.New("peer certificate URI SAN is not a SPIFFE ID")
	}
	if uriSAN.Port() != "" {
		return "", "", errors.New("peer certificate URI SAN cannot have a port")
	}
	return uriSAN.String(), (&url.URL{
		Scheme: "spiffe",
		Host:   uriSAN.Host,
	}).String(), nil
}
