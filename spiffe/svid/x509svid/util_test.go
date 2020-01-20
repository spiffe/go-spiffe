package x509svid

import (
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetIDsFromCertificate covers invalid URI count.
// Other conditions are already covered by other tests in the package.
func TestGetIDsFromCertificate(t *testing.T) {
	tests := []struct {
		expectedError string
		giveURIs      []*url.URL
	}{
		{
			expectedError: "peer certificate contains no URI SAN",
		},
		{
			expectedError: "peer certificate contains more than one URI SAN",
			giveURIs: []*url.URL{
				&url.URL{Scheme: "https", Host: "example.com"},
				&url.URL{Scheme: "spiffe", Host: "example.net"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.expectedError, func(t *testing.T) {
			giveCert := &x509.Certificate{
				URIs: test.giveURIs,
			}

			id, domain, err := GetIDsFromCertificate(giveCert)
			assert.Empty(t, id)
			assert.Empty(t, domain)
			assert.EqualError(t, err, test.expectedError)
		})
	}
}
