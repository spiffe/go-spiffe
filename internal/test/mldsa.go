//go:build go1.27

package test

import (
	"crypto"
	"crypto/mldsa"
	"testing"

	"github.com/stretchr/testify/require"
)

var mldsaParameters = map[string]mldsa.Parameters{
	"ML-DSA-44": mldsa.MLDSA44(),
	"ML-DSA-65": mldsa.MLDSA65(),
	"ML-DSA-87": mldsa.MLDSA87(),
}

// NewMLDSAKey returns an ML-DSA key for the named parameter set (one of
// MLDSAParameters). On Go versions before 1.27 it skips the test.
func NewMLDSAKey(tb testing.TB, params string) crypto.Signer {
	p, ok := mldsaParameters[params]
	require.True(tb, ok, "unknown ML-DSA parameter set %q", params)
	key, err := mldsa.GenerateKey(p)
	require.NoError(tb, err)
	return key
}

// MLDSAParameterSet returns the parameter set name of an ML-DSA public or
// private key, and false for any other key.
func MLDSAParameterSet(key any) (string, bool) {
	switch key := key.(type) {
	case *mldsa.PrivateKey:
		return key.PublicKey().Parameters().String(), true
	case *mldsa.PublicKey:
		return key.Parameters().String(), true
	}
	return "", false
}
