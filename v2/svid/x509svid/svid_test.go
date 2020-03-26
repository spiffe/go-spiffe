package x509svid_test

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fileSet struct {
	certPathPEM string
	certPathDER string
	keyPathPEM  string
	keyPathDER  string
}

var (
	fileSetSingleCert fileSet = fileSet{
		certPathPEM: "testdata/certificate-1.pem",
		certPathDER: "testdata/certificate-1.der",
		keyPathPEM:  "testdata/key-1.pem",
		keyPathDER:  "testdata/key-1.der",
	}
	fileSetMultipleCerts fileSet = fileSet{
		certPathPEM: "testdata/certificate-2.pem",
		certPathDER: "testdata/certificate-2.der",
		keyPathPEM:  "testdata/key-2.pem",
		keyPathDER:  "testdata/key-2.der",
	}
	fileSetCorruptedCert fileSet = fileSet{
		certPathPEM: "testdata/corrupted",
		certPathDER: "testdata/corrupted",
		keyPathPEM:  "testdata/key-1.pem",
		keyPathDER:  "testdata/key-1.der",
	}
	fileSetCorruptedKey fileSet = fileSet{
		certPathPEM: "testdata/certificate-1.pem",
		certPathDER: "testdata/certificate-1.der",
		keyPathPEM:  "testdata/corrupted",
		keyPathDER:  "testdata/corrupted",
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
			expErrContains: "x509svid: no certificates found",
		},
		{
			name:           "Missing private key",
			fs:             fileSetMissingKey,
			expErrContains: "x509svid: no private key found",
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
			name:           "Certificate without SPIFFE ID",
			fs:             fileSetCertWithoutID,
			expErrContains: "x509svid: cannot get SPIFFE ID: certificate does not contain URIs",
		},
		{
			name:           "Certificate with wrong SPIFFE ID",
			fs:             fileSetCertWrongID,
			expErrContains: "x509svid: cannot get SPIFFE ID: unable to parse ID",
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

func TestMarshal_Succeeds(t *testing.T) {
	certBytes, err := ioutil.ReadFile("testdata/certificate-1.pem")
	require.NoError(t, err)
	keyBytes, err := ioutil.ReadFile("testdata/key-1.pem")
	require.NoError(t, err)
	svid, err := x509svid.Parse(certBytes, keyBytes)
	require.NoError(t, err)

	mCertBytes, mKeyBytes, err := svid.Marshal()
	require.NoError(t, err)
	require.Equal(t, certBytes, mCertBytes)
	require.Equal(t, keyBytes, mKeyBytes)
}

func TestMarshal_Fails(t *testing.T) {
	svid, err := x509svid.Load("testdata/certificate-1.pem", "testdata/key-1.pem")
	require.NoError(t, err)
	svid.PrivateKey = nil // Set private key to nil to force an error
	mCertBytes, mKeyBytes, err := svid.Marshal()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot encode private key")
	assert.Nil(t, mCertBytes)
	assert.Nil(t, mKeyBytes)
}

func TestGetX509SVID(t *testing.T) {
	s, err := x509svid.Load("testdata/certificate-1.pem", "testdata/key-1.pem")
	require.NoError(t, err)
	svid, err := s.GetX509SVID()
	require.NoError(t, err)
	assert.Equal(t, s, svid)
}

func TestMarshalRaw_Succeeds(t *testing.T) {
	s, err := x509svid.Load("testdata/certificate-1.pem", "testdata/key-1.pem")
	require.NoError(t, err)

	rawCert, rawKey, err := s.MarshalRaw()
	require.NoError(t, err)
	require.NotNil(t, rawCert)
	require.NotNil(t, rawKey)

	expRawCert, err := ioutil.ReadFile("testdata/certificate-1.der")
	require.NoError(t, err)
	assert.Equal(t, expRawCert, rawCert)

	expRawKey, err := ioutil.ReadFile("testdata/key-1.der")
	require.NoError(t, err)
	assert.Equal(t, expRawKey, rawKey)
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

			expRawCert, err := ioutil.ReadFile(test.fs.certPathDER)
			require.NoError(t, err)
			assert.Equal(t, expRawCert, rawCert)

			expRawKey, err := ioutil.ReadFile(test.fs.keyPathDER)
			require.NoError(t, err)
			assert.Equal(t, expRawKey, rawKey)
		})
	}
}

func TestParseRaw(t *testing.T) {
	tests := []struct {
		name           string
		fs             fileSet
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
			name:           "Certificate bytes are not DER encoded",
			fs:             fileSetCorruptedCert,
			expErrContains: "x509svid: cannot parse DER encoded certificate",
		},
		{
			name:           "Key bytes are not DER encoded",
			fs:             fileSetCorruptedKey,
			expErrContains: "x509svid: cannot parse DER encoded private key",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			rawCert, err := ioutil.ReadFile(test.fs.certPathDER)
			require.NoError(t, err)
			rawKey, err := ioutil.ReadFile(test.fs.keyPathDER)
			require.NoError(t, err)

			svid, err := x509svid.ParseRaw(rawCert, rawKey)
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
