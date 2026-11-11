package cryptoutil_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/spiffe/go-spiffe/v2/internal/cryptoutil"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/stretchr/testify/require"
)

func TestPublicKeyEqual(t *testing.T) {
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey1 := test.NewEC256Key(t)
	ecKey2 := test.NewEC256Key(t)
	edKey1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mldsa44Key1 := test.NewMLDSAKey(t, test.MLDSAParameters[0])
	mldsa44Key2 := test.NewMLDSAKey(t, test.MLDSAParameters[0])
	mldsa65Key := test.NewMLDSAKey(t, test.MLDSAParameters[1])
	mldsa87Key := test.NewMLDSAKey(t, test.MLDSAParameters[2])
	ecdhKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	for _, tt := range []struct {
		name  string
		a, b  crypto.PublicKey
		equal bool
		err   string
	}{
		{name: "RSA same", a: rsaKey1.Public(), b: rsaKey1.Public(), equal: true},
		{name: "RSA different", a: rsaKey1.Public(), b: rsaKey2.Public()},
		{name: "ECDSA same", a: ecKey1.Public(), b: ecKey1.Public(), equal: true},
		{name: "ECDSA different", a: ecKey1.Public(), b: ecKey2.Public()},
		{name: "Ed25519 same", a: edKey1, b: edKey1, equal: true},
		{name: "Ed25519 different", a: edKey1, b: edKey2},
		{name: "ML-DSA-44 same", a: mldsa44Key1.Public(), b: mldsa44Key1.Public(), equal: true},
		{name: "ML-DSA-44 different", a: mldsa44Key1.Public(), b: mldsa44Key2.Public()},
		{name: "ML-DSA-65 same", a: mldsa65Key.Public(), b: mldsa65Key.Public(), equal: true},
		{name: "ML-DSA-87 same", a: mldsa87Key.Public(), b: mldsa87Key.Public(), equal: true},
		{name: "ML-DSA different parameter sets", a: mldsa44Key1.Public(), b: mldsa65Key.Public()},
		{name: "ML-DSA vs ECDSA", a: mldsa44Key1.Public(), b: ecKey1.Public()},
		{name: "ECDSA vs ML-DSA", a: ecKey1.Public(), b: mldsa44Key1.Public()},
		{name: "unsupported type", a: ecdhKey.PublicKey(), b: ecdhKey.PublicKey(), err: "unsupported public key type *ecdh.PublicKey"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			equal, err := cryptoutil.PublicKeyEqual(tt.a, tt.b)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.equal, equal)
		})
	}
}
