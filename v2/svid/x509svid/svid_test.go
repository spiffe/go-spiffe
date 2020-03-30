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

type fileSet struct {
	certPathPEM string
	keyPathPEM  string
}

var (
	fileSetSingleCert fileSet = fileSet{
		certPathPEM: "testdata/certificate-1.pem",
		keyPathPEM:  "testdata/key-1.pem",
	}
	fileSetMultipleCerts fileSet = fileSet{
		certPathPEM: "testdata/certificate-2.pem",
		keyPathPEM:  "testdata/key-2.pem",
	}
	fileSetCorruptedCert fileSet = fileSet{
		certPathPEM: "testdata/corrupted",
		keyPathPEM:  "testdata/key-1.pem",
	}
	fileSetCorruptedKey fileSet = fileSet{
		certPathPEM: "testdata/certificate-1.pem",
		keyPathPEM:  "testdata/corrupted",
	}
	fileSetKeyAndCertSameFile fileSet = fileSet{
		certPathPEM: "testdata/key-and-certificate.pem",
		keyPathPEM:  "testdata/key-and-certificate.pem",
	}
	fileSetCertAndKeySameFile fileSet = fileSet{
		certPathPEM: "testdata/certificate-and-key.pem",
		keyPathPEM:  "testdata/certificate-and-key.pem",
	}
	fileSetMissingCert fileSet = fileSet{
		certPathPEM: "testdata/key-1.pem",
		keyPathPEM:  "testdata/key-1.pem",
	}
	fileSetMissingKey fileSet = fileSet{
		certPathPEM: "testdata/certificate-1.pem",
		keyPathPEM:  "testdata/certificate-1.pem",
	}
	fileSetCertKeyMissmatch fileSet = fileSet{
		certPathPEM: "testdata/certificate-1.pem",
		keyPathPEM:  "testdata/key-2.pem",
	}
	fileSetCertWithoutID fileSet = fileSet{
		certPathPEM: "testdata/certificate-without-id.pem",
		keyPathPEM:  "testdata/key-1.pem",
	}
	fileSetCertWrongID fileSet = fileSet{
		certPathPEM: "testdata/certificate-with-wrong-id.pem",
		keyPathPEM:  "testdata/key-1.pem",
	}
)

func TestLoad_Succeds(t *testing.T) {
	svid, err := x509svid.Load("testdata/certificate-1.pem", "testdata/key-1.pem")
	require.NoError(t, err)
	require.NotNil(t, svid)
	require.Equal(t, svid.ID.String(), "spiffe://example.org/workload-1")
}

func TestLoad_FailsCannotReadCertFile(t *testing.T) {
	svid, err := x509svid.Load("testdata/non-existent.pem", "testdata/key-1.pem")
	require.Error(t, err)
	require.Nil(t, svid)
	require.Contains(t, err.Error(), "cannot read certificate file:")
	require.True(t, errors.Is(err, os.ErrNotExist))
}

func TestLoad_FailsCannotReadKeyFile(t *testing.T) {
	svid, err := x509svid.Load("testdata/certificate-1.pem", "testdata/non-existent.pem")
	require.Error(t, err)
	require.Nil(t, svid)
	require.Contains(t, err.Error(), "cannot read key file:")
	require.True(t, errors.Is(err, os.ErrNotExist))
}

func TestParse(t *testing.T) {
	tests := []struct {
		name           string
		fs             fileSet
		expID          spiffeid.ID
		expNumCerts    int
		expErrContains string
	}{
		{
			name:        "Single certificate and key",
			fs:          fileSetSingleCert,
			expID:       spiffeid.Must("example.org", "workload-1"),
			expNumCerts: 1,
		},
		{
			name:        "Certificate with intermediate and key",
			fs:          fileSetMultipleCerts,
			expID:       spiffeid.Must("example.org", "workload-1"),
			expNumCerts: 2,
		},
		{
			name:        "Key and certificate in the same byte array",
			fs:          fileSetKeyAndCertSameFile,
			expID:       spiffeid.Must("example.org", "workload-1"),
			expNumCerts: 1,
		},
		{
			name:        "Certificate and Key in the same byte array",
			fs:          fileSetCertAndKeySameFile,
			expID:       spiffeid.Must("example.org", "workload-1"),
			expNumCerts: 1,
		},
		{
			name:           "Missing certificate",
			fs:             fileSetMissingCert,
			expErrContains: "x509svid: certificate validation failed: no certificates found",
		},
		{
			name:           "Missing private key",
			fs:             fileSetMissingKey,
			expErrContains: "x509svid: private key validation failed: no private key found",
		},
		{
			name:           "Corrupted private key",
			fs:             fileSetCorruptedKey,
			expErrContains: "x509svid: cannot parse PEM encoded private key: no PEM data found while decoding block",
		},
		{
			name:           "Corrupted certificate",
			fs:             fileSetCorruptedCert,
			expErrContains: "x509svid: cannot parse PEM encoded certificate: no PEM data found while decoding block",
		},
		{
			name:           "Certificate does not match private key",
			fs:             fileSetCertKeyMissmatch,
			expErrContains: "x509svid: private key validation failed: leaf certificate does not match private key",
		},
		{
			name:           "Certificate without SPIFFE ID",
			fs:             fileSetCertWithoutID,
			expErrContains: "x509svid: certificate validation failed: cannot get leaf certificate SPIFFE ID: leaf certificate contains no URI SAN",
		},
		{
			name:           "Certificate with wrong SPIFFE ID",
			fs:             fileSetCertWrongID,
			expErrContains: "x509svid: certificate validation failed: cannot get leaf certificate SPIFFE ID: spiffeid: invalid scheme",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			certBytes, err := ioutil.ReadFile(test.fs.certPathPEM)
			require.NoError(t, err)

			keyBytes, err := ioutil.ReadFile(test.fs.keyPathPEM)
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
	s, err := x509svid.Load("testdata/certificate-1.pem", "testdata/key-1.pem")
	require.NoError(t, err)
	svid, err := s.GetX509SVID()
	require.NoError(t, err)
	assert.Equal(t, s, svid)
}

func TestMarshal(t *testing.T) {
	tests := []struct {
		name           string
		fs             fileSet
		modifySVID     func(*x509svid.SVID)
		expErrContains string
	}{
		{
			name: "Single certificate and key",
			fs:   fileSetSingleCert,
		},
		{
			name: "Multiple certificates and key",
			fs:   fileSetMultipleCerts,
		},
		{
			name:           "Fails to encode private key",
			fs:             fileSetSingleCert,
			expErrContains: "cannot encode private key",
			modifySVID: func(s *x509svid.SVID) {
				s.PrivateKey = nil // Set private key to nil to force an error
			},
		},
		{
			name:           "Fails to marshal certificates",
			fs:             fileSetSingleCert,
			expErrContains: "no certificates to marshal",
			modifySVID: func(s *x509svid.SVID) {
				s.Certificates = nil // Set certificates to nil to force an error
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			s, err := x509svid.Load(test.fs.certPathPEM, test.fs.keyPathPEM)
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

			expCerts, err := ioutil.ReadFile(test.fs.certPathPEM)
			require.NoError(t, err)
			assert.Equal(t, expCerts, certs)

			expKey, err := ioutil.ReadFile(test.fs.keyPathPEM)
			require.NoError(t, err)
			assert.Equal(t, expKey, key)
		})
	}
}

func TestMarshalRaw(t *testing.T) {
	tests := []struct {
		name           string
		fs             fileSet
		modifySVID     func(*x509svid.SVID)
		expErrContains string
	}{
		{
			name: "Single certificate and key",
			fs:   fileSetSingleCert,
		},
		{
			name: "Multiple certificates and key",
			fs:   fileSetMultipleCerts,
		},
		{
			name:           "Fails to marshal private key",
			fs:             fileSetSingleCert,
			expErrContains: "cannot marshal private key",
			modifySVID: func(s *x509svid.SVID) {
				s.PrivateKey = nil // Set private key to nil to force an error
			},
		},
		{
			name:           "Fails to marshal certificates",
			fs:             fileSetSingleCert,
			expErrContains: "no certificates to marshal",
			modifySVID: func(s *x509svid.SVID) {
				s.Certificates = nil // Set private key to nil to force an error
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			s, err := x509svid.Load(test.fs.certPathPEM, test.fs.keyPathPEM)
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

			expRawCert := loadRawCertificates(t, test.fs.certPathPEM)
			assert.Equal(t, expRawCert, rawCert)
			expRawKey := loadRawKey(t, test.fs.keyPathPEM)
			assert.Equal(t, expRawKey, rawKey)
		})
	}
}

func TestParseRaw(t *testing.T) {
	tests := []struct {
		name           string
		fs             fileSet
		rawCerts       []byte
		rawKey         []byte
		expErrContains string
	}{
		{
			name:     "Single certificate and key",
			fs:       fileSetSingleCert,
			rawCerts: loadRawCertificates(t, fileSetSingleCert.certPathPEM),
			rawKey:   loadRawKey(t, fileSetSingleCert.keyPathPEM),
		},
		{
			name:     "Multiple certificates and key",
			fs:       fileSetMultipleCerts,
			rawCerts: loadRawCertificates(t, fileSetMultipleCerts.certPathPEM),
			rawKey:   loadRawKey(t, fileSetMultipleCerts.keyPathPEM),
		},
		{
			name:           "Certificate bytes are not DER encoded",
			rawCerts:       []byte("not-DER-encoded"),
			rawKey:         loadRawKey(t, fileSetSingleCert.keyPathPEM),
			expErrContains: "x509svid: cannot parse DER encoded certificate",
		},
		{
			name:           "Key bytes are not DER encoded",
			rawCerts:       loadRawCertificates(t, fileSetSingleCert.certPathPEM),
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
			expectedSVID, err := x509svid.Load(test.fs.certPathPEM, test.fs.keyPathPEM)
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
