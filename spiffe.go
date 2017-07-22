package spiffe

import (
	"crypto/x509"
	"encoding/pem"
	"encoding/asn1"
	"crypto/x509/pkix"
	"errors"
)

var oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

func getExtensionsFromAsn1ObjectIdentifier(certificate *x509.Certificate, id asn1.ObjectIdentifier) []pkix.Extension {
	var extensions []pkix.Extension
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(id) {
			extensions = append(extensions, extension)
		}
	}
	return extensions
}

func GetSubjectAltName(certificateString string) (san string, err error) {
	block, _ := pem.Decode([]byte(certificateString))
	if block == nil {
		return "", errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", errors.New("failed to parse certificate: " + err.Error())
	}

	if len(cert.Extensions) > 0 {
		for _, extension := range getExtensionsFromAsn1ObjectIdentifier(cert, oidExtensionSubjectAltName) {
			return string(extension.Value[:]), nil
		}
	}

	return "", nil
}