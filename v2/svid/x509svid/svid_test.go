package x509svid_test

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/spiffe/go-spiffe/v2/internal/pemutil"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	keyRSA                 = "testdata/key-pkcs8-rsa.pem"
	certSingle             = "testdata/good-leaf-only.pem"
	leafNoDigitalSignature = "testdata/wrong-leaf-no-digital-signature.pem"
	leafCRLSign            = "testdata/wrong-leaf-crl-sign.pem"
	leafCertSign           = "testdata/wrong-leaf-cert-sign.pem"
	leafCAtrue             = "testdata/wrong-leaf-ca-true.pem"
	leafEmptyID            = "testdata/wrong-leaf-empty-id.pem"
	signNoCA               = "testdata/wrong-intermediate-no-ca.pem"
	signNoKeyCertSign      = "testdata/wrong-intermediate-no-key-cert-sign.pem"

	keyECDSA     = "testdata/key-pkcs8-ecdsa.pem"
	certMultiple = "testdata/good-leaf-and-intermediate.pem"

	certAndKey = "testdata/good-cert-and-key.pem"
	keyAndCert = "testdata/good-key-and-cert.pem"
	corrupted  = "testdata/corrupted"
)

func TestLoad_Succeeds(t *testing.T) {
	svid, err := x509svid.Load(certSingle, keyRSA)
	require.NoError(t, err)
	require.NotNil(t, svid)
	require.Equal(t, svid.ID.String(), "spiffe://example.org/workload-1")
}

func TestLoad_FailsCannotReadCertFile(t *testing.T) {
	svid, err := x509svid.Load("testdata/non-existent.pem", keyRSA)
	require.Error(t, err)
	require.Nil(t, svid)
	require.Contains(t, err.Error(), "cannot read certificate file:")
	require.True(t, errors.Is(err, os.ErrNotExist))
}

func TestLoad_FailsCannotReadKeyFile(t *testing.T) {
	svid, err := x509svid.Load(certSingle, "testdata/non-existent.pem")
	require.Error(t, err)
	require.Nil(t, svid)
	require.Contains(t, err.Error(), "cannot read key file:")
	require.True(t, errors.Is(err, os.ErrNotExist))
}

func TestParse(t *testing.T) {
	tests := []struct {
		name           string
		keyPath        string
		certsPath      string
		expID          spiffeid.ID
		expNumCerts    int
		expErrContains string
	}{
		{
			name:        "Single certificate and key",
			keyPath:     keyRSA,
			certsPath:   certSingle,
			expID:       spiffeid.Must("example.org", "workload-1"),
			expNumCerts: 1,
		},
		{
			name:        "Certificate with intermediate and key",
			keyPath:     keyECDSA,
			certsPath:   certMultiple,
			expID:       spiffeid.Must("example.org", "workload-1"),
			expNumCerts: 2,
		},
		{
			name:        "Key and certificate in the same byte array",
			keyPath:     keyAndCert,
			certsPath:   keyAndCert,
			expID:       spiffeid.Must("example.org", "workload-1"),
			expNumCerts: 1,
		},
		{
			name:        "Certificate and Key in the same byte array",
			keyPath:     certAndKey,
			certsPath:   certAndKey,
			expID:       spiffeid.Must("example.org", "workload-1"),
			expNumCerts: 1,
		},
		{
			name:           "Missing certificate",
			keyPath:        keyRSA,
			certsPath:      keyRSA,
			expErrContains: "x509svid: certificate validation failed: no certificates found",
		},
		{
			name:           "Missing private key",
			keyPath:        certSingle,
			certsPath:      certSingle,
			expErrContains: "x509svid: private key validation failed: no private key found",
		},
		{
			name:           "Corrupted private key",
			keyPath:        corrupted,
			certsPath:      certSingle,
			expErrContains: "x509svid: cannot parse PEM encoded private key: no PEM data found while decoding block",
		},
		{
			name:           "Corrupted certificate",
			keyPath:        keyRSA,
			certsPath:      corrupted,
			expErrContains: "x509svid: cannot parse PEM encoded certificate: no PEM data found while decoding block",
		},
		{
			name:           "Certificate does not match private key",
			keyPath:        keyRSA,
			certsPath:      certMultiple,
			expErrContains: "x509svid: private key validation failed: leaf certificate does not match private key",
		},
		{
			name:           "Certificate without SPIFFE ID",
			keyPath:        keyRSA,
			certsPath:      leafEmptyID,
			expErrContains: "x509svid: certificate validation failed: cannot get leaf certificate SPIFFE ID: certificate contains no URI SAN",
		},
		{
			name:           "Leaf certificate with CA flag set to true",
			certsPath:      leafCAtrue,
			keyPath:        keyRSA,
			expErrContains: "x509svid: certificate validation failed: leaf certificate must not have CA flag set to true",
		},
		{
			name:           "Leaf certificate without digitalSignature as key usage",
			certsPath:      leafNoDigitalSignature,
			keyPath:        keyRSA,
			expErrContains: "x509svid: certificate validation failed: leaf certificate must have 'digitalSignature' set as key usage",
		},
		{
			name:           "Leaf certificate with certSign as key usage",
			certsPath:      leafCertSign,
			keyPath:        keyRSA,
			expErrContains: "x509svid: certificate validation failed: leaf certificate must not have 'keyCertSign' set as key usage",
		},
		{
			name:           "Leaf certificate with cRLSign as key usage",
			certsPath:      leafCRLSign,
			keyPath:        keyRSA,
			expErrContains: "x509svid: certificate validation failed: leaf certificate must not have 'cRLSign' set as key usage",
		},
		{
			name:           "Signing certificate without CA flag",
			certsPath:      signNoCA,
			keyPath:        keyRSA,
			expErrContains: "x509svid: certificate validation failed: signing certificate must have CA flag set to true",
		},
		{
			name:           "Signing certificate without 'keyCertSign' usage",
			certsPath:      signNoKeyCertSign,
			keyPath:        keyRSA,
			expErrContains: "x509svid: certificate validation failed: signing certificate must have 'keyCertSign' set as key usage",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			certBytes, err := ioutil.ReadFile(test.certsPath)
			require.NoError(t, err)

			keyBytes, err := ioutil.ReadFile(test.keyPath)
			require.NoError(t, err)

			svid, err := x509svid.Parse(certBytes, keyBytes)
			if test.expErrContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expErrContains)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, svid)
			assert.Equal(t, test.expID, svid.ID)
			assert.Len(t, svid.Certificates, test.expNumCerts)
			assert.Equal(t, svid.PrivateKey.Public(), svid.Certificates[0].PublicKey)
		})
	}
}

func TestGetX509SVID(t *testing.T) {
	s, err := x509svid.Load(certSingle, keyRSA)
	require.NoError(t, err)
	svid, err := s.GetX509SVID()
	require.NoError(t, err)
	assert.Equal(t, s, svid)
}

func TestMarshal(t *testing.T) {
	tests := []struct {
		name           string
		keyPath        string
		certsPath      string
		modifySVID     func(*x509svid.SVID)
		expErrContains string
	}{
		{
			name:      "Single certificate and key",
			keyPath:   keyRSA,
			certsPath: certSingle,
		},
		{
			name:      "Multiple certificates and key",
			keyPath:   keyECDSA,
			certsPath: certMultiple,
		},
		{
			name:           "Fails to encode private key",
			keyPath:        keyRSA,
			certsPath:      certSingle,
			expErrContains: "cannot encode private key",
			modifySVID: func(s *x509svid.SVID) {
				s.PrivateKey = nil // Set private key to nil to force an error
			},
		},
		{
			name:           "Fails to marshal certificates",
			keyPath:        keyRSA,
			certsPath:      certSingle,
			expErrContains: "no certificates to marshal",
			modifySVID: func(s *x509svid.SVID) {
				s.Certificates = nil // Set certificates to nil to force an error
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			s, err := x509svid.Load(test.certsPath, test.keyPath)
			require.NoError(t, err)

			if test.modifySVID != nil {
				test.modifySVID(s)
			}

			certs, key, err := s.Marshal()
			if test.expErrContains != "" {
				require.Error(t, err)
				require.Nil(t, certs)
				require.Nil(t, key)
				assert.Contains(t, err.Error(), test.expErrContains)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, certs)
			require.NotNil(t, key)

			expCerts, err := ioutil.ReadFile(test.certsPath)
			require.NoError(t, err)
			assert.Equal(t, expCerts, certs)

			expKey, err := ioutil.ReadFile(test.keyPath)
			require.NoError(t, err)
			assert.Equal(t, expKey, key)
		})
	}
}

func TestMarshalRaw(t *testing.T) {
	tests := []struct {
		name           string
		keyPath        string
		certsPath      string
		modifySVID     func(*x509svid.SVID)
		expErrContains string
	}{
		{
			name:      "Single certificate and key",
			keyPath:   keyRSA,
			certsPath: certSingle,
		},
		{
			name:      "Multiple certificates and key",
			keyPath:   keyECDSA,
			certsPath: certMultiple,
		},
		{
			name:           "Fails to marshal private key",
			keyPath:        keyRSA,
			certsPath:      certSingle,
			expErrContains: "cannot marshal private key",
			modifySVID: func(s *x509svid.SVID) {
				s.PrivateKey = nil // Set private key to nil to force an error
			},
		},
		{
			name:           "Fails to marshal certificates",
			keyPath:        keyRSA,
			certsPath:      certSingle,
			expErrContains: "no certificates to marshal",
			modifySVID: func(s *x509svid.SVID) {
				s.Certificates = nil // Set private key to nil to force an error
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			s, err := x509svid.Load(test.certsPath, test.keyPath)
			require.NoError(t, err)

			if test.modifySVID != nil {
				test.modifySVID(s)
			}

			rawCert, rawKey, err := s.MarshalRaw()
			if test.expErrContains != "" {
				require.Error(t, err)
				require.Nil(t, rawCert)
				require.Nil(t, rawKey)
				assert.Contains(t, err.Error(), test.expErrContains)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, rawCert)
			require.NotNil(t, rawKey)

			expRawCert := loadRawCertificates(t, test.certsPath)
			assert.Equal(t, expRawCert, rawCert)
			expRawKey := loadRawKey(t, test.keyPath)
			assert.Equal(t, expRawKey, rawKey)
		})
	}
}

func TestParseRaw(t *testing.T) {
	tests := []struct {
		name           string
		keyPath        string
		certsPath      string
		rawCerts       []byte
		rawKey         []byte
		expErrContains string
	}{
		{
			name:      "Single certificate and key",
			keyPath:   keyRSA,
			certsPath: certSingle,
			rawCerts:  loadRawCertificates(t, certSingle),
			rawKey:    loadRawKey(t, keyRSA),
		},
		{
			name:      "Multiple certificates and key",
			keyPath:   keyECDSA,
			certsPath: certMultiple,
			rawCerts:  loadRawCertificates(t, certMultiple),
			rawKey:    loadRawKey(t, keyECDSA),
		},
		{
			name:           "Certificate bytes are not DER encoded",
			rawCerts:       []byte("not-DER-encoded"),
			rawKey:         loadRawKey(t, keyRSA),
			expErrContains: "x509svid: cannot parse DER encoded certificate",
		},
		{
			name:           "Key bytes are not DER encoded",
			rawCerts:       loadRawCertificates(t, certSingle),
			rawKey:         []byte("not-DER-encoded"),
			expErrContains: "x509svid: cannot parse DER encoded private key",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			svid, err := x509svid.ParseRaw(test.rawCerts, test.rawKey)
			if test.expErrContains != "" {
				require.Error(t, err)
				require.Nil(t, svid)
				assert.Contains(t, err.Error(), test.expErrContains)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, svid)
			expectedSVID, err := x509svid.Load(test.certsPath, test.keyPath)
			require.NoError(t, err)
			assert.Equal(t, expectedSVID, svid)
		})
	}
}

func loadRawCertificates(t *testing.T, path string) []byte {
	certsBytes, err := ioutil.ReadFile(path)
	require.NoError(t, err)

	certs, err := pemutil.ParseCertificates(certsBytes)
	require.NoError(t, err)

	var rawBytes []byte
	for _, cert := range certs {
		rawBytes = append(rawBytes, cert.Raw...)
	}
	return rawBytes
}

func loadRawKey(t *testing.T, path string) []byte {
	keyBytes, err := ioutil.ReadFile(path)
	require.NoError(t, err)

	key, err := pemutil.ParsePrivateKey(keyBytes)
	require.NoError(t, err)

	rawKey, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return rawKey
}
