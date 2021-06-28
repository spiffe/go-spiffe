package pemutil_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/spiffe/go-spiffe/v2/internal/pemutil"
	"github.com/stretchr/testify/require"
)

var (
	testCertsPEM = []byte(`-----BEGIN CERTIFICATE-----
MIH0MIGboAMCAQICAQEwCgYIKoZIzj0EAwIwADAiGA8wMDAxMDEwMTAwMDAwMFoY
DzAwMDEwMTAxMDAwMDAwWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElb3Z
CIuzbVMQsWP1b0snmJxNkpG9xT8ZHt88byGhJsde2y0zoOld9+soPZpjLBehx2Wf
6pTc22/r61HCoIFkfaMCMAAwCgYIKoZIzj0EAwIDSAAwRQIhANztuW3qmu/UfoXQ
97bYXmIunEIRPSowxAcruqO46GqhAiBSxPFst6yb3cIRwDnr4rBfaUb13NigI1iK
TM0VOlcTxg==
-----END CERTIFICATE-----
`)
	testCerts, _ = x509.ParseCertificates(pemBlockData(testCertsPEM))

	testKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsswWk0ZyjTDMD7zL
zUFjYzbfrouQgIAitSmJMnHQcyqhRANCAASVvdkIi7NtUxCxY/VvSyeYnE2Skb3F
Pxke3zxvIaEmx17bLTOg6V336yg9mmMsF6HHZZ/qlNzbb+vrUcKggWR9
-----END PRIVATE KEY-----
`)
	testKey, _ = x509.ParsePKCS8PrivateKey(pemBlockData(testKeyPEM))
)

func TestEncodeCertificates(t *testing.T) {
	actualPEM := pemutil.EncodeCertificates(testCerts)
	require.Equal(t, testCertsPEM, actualPEM)
}

func TestEncodePKCSPrivateKey(t *testing.T) {
	actualPEM, err := pemutil.EncodePKCS8PrivateKey(testKey)
	require.NoError(t, err)
	require.Equal(t, testKeyPEM, actualPEM)
}

func TestParseCertificates(t *testing.T) {
	filler := []byte("filler\n")

	t.Run("empty", func(t *testing.T) {
		_, err := pemutil.ParseCertificates(nil)
		require.EqualError(t, err, "no PEM blocks found")
	})

	t.Run("only filler", func(t *testing.T) {
		_, err := pemutil.ParseCertificates(filler)
		require.EqualError(t, err, "no PEM blocks found")
	})

	t.Run("without filler", func(t *testing.T) {
		certs, err := pemutil.ParseCertificates(testCertsPEM)
		require.NoError(t, err)
		require.Equal(t, testCerts, certs)
	})

	t.Run("with filler", func(t *testing.T) {
		certs, err := pemutil.ParseCertificates(concatBytes(filler, testCertsPEM, filler))
		require.NoError(t, err)
		require.Equal(t, testCerts, certs)
	})

	t.Run("before key", func(t *testing.T) {
		certs, err := pemutil.ParseCertificates(concatBytes(testCertsPEM, testKeyPEM))
		require.NoError(t, err)
		require.Equal(t, testCerts, certs)
	})

	t.Run("after key", func(t *testing.T) {
		certs, err := pemutil.ParseCertificates(concatBytes(testKeyPEM, testCertsPEM))
		require.NoError(t, err)
		require.Equal(t, testCerts, certs)
	})
}

func TestParsePrivateKey(t *testing.T) {
	filler := []byte("filler\n")

	t.Run("empty", func(t *testing.T) {
		_, err := pemutil.ParsePrivateKey(nil)
		require.EqualError(t, err, "no PEM blocks found")
	})

	t.Run("only filler", func(t *testing.T) {
		_, err := pemutil.ParsePrivateKey(filler)
		require.EqualError(t, err, "no PEM blocks found")
	})

	t.Run("without filler", func(t *testing.T) {
		key, err := pemutil.ParsePrivateKey(testKeyPEM)
		require.NoError(t, err)
		require.Equal(t, testKey, key)
	})

	t.Run("with filler", func(t *testing.T) {
		key, err := pemutil.ParsePrivateKey(concatBytes(filler, testKeyPEM, filler))
		require.NoError(t, err)
		require.Equal(t, testKey, key)
	})

	t.Run("before certificate", func(t *testing.T) {
		key, err := pemutil.ParsePrivateKey(concatBytes(testKeyPEM, testCertsPEM))
		require.NoError(t, err)
		require.Equal(t, testKey, key)
	})

	t.Run("after certificate", func(t *testing.T) {
		key, err := pemutil.ParsePrivateKey(concatBytes(testCertsPEM, testKeyPEM))
		require.NoError(t, err)
		require.Equal(t, testKey, key)
	})
}

func pemBlockData(data []byte) (out []byte) {
	blocks, _ := decodePEM(data)
	for _, block := range blocks {
		if block != nil {
			out = append(out, block.Bytes...)
		}
	}
	return out
}

func decodePEM(data []byte) (blocks []*pem.Block, extra [][]byte) {
	for {
		block, rest := pem.Decode(data)
		blocks = append(blocks, block)
		extra = append(extra, rest)
		if block == nil {
			return blocks, extra
		}
		data = rest
	}
}

func concatBytes(bs ...[]byte) []byte {
	return bytes.Join(bs, nil)
}
