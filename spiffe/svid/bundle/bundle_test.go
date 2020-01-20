package bundle

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	trustDomain := "spiffe://trustDomain1.com"
	bundle := New(trustDomain)

	expectedBundle := &Bundle{
		TrustDomainID: trustDomain,
		JWTKeys:       map[string]crypto.PublicKey{},
	}

	require.Equal(t, expectedBundle, bundle)
}

func TestFindJWTKeys(t *testing.T) {
	// Create keys
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create bundle
	bundle1 := &Bundle{
		TrustDomainID: "spiffe://trustDomain1.com",
		RootCAs:       []*x509.Certificate{},
		JWTKeys: map[string]crypto.PublicKey{
			"key1": key1,
			"key2": key2,
		},
	}

	bundle2 := &Bundle{
		TrustDomainID: "spiffe://trustDomain2.com",
		RootCAs:       []*x509.Certificate{},
		JWTKeys: map[string]crypto.PublicKey{
			"key1": key1,
		},
	}

	// Add all bundles inside a bundles instances
	bundles := Bundles{
		bundle1.TrustDomainID: bundle1,
		bundle2.TrustDomainID: bundle2,
	}

	testCases := []struct {
		name          string
		trustDomainID string
		keyID         string
		err           string
		jwtKey        crypto.PublicKey
	}{
		{
			name:          "trustdomain not found",
			trustDomainID: "spiffe://someinvalidtd.com",
			keyID:         "key1",
			err:           "no keys found for trust domain \"spiffe://someinvalidtd.com\"",
		},
		{
			name:          "key not found",
			trustDomainID: "spiffe://trustDomain2.com",
			keyID:         "key2",
			err:           "public key \"key2\" not found in trust domain \"spiffe://trustDomain2.com\"",
		},
		{
			name:          "success",
			trustDomainID: "spiffe://trustDomain1.com",
			keyID:         "key2",
			jwtKey:        key2,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			jwtKey, err := bundles.FindJWTKey(testCase.trustDomainID, testCase.keyID)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				require.Nil(t, jwtKey)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.jwtKey, jwtKey)
		})
	}
}
