//go:build !go1.27

package test

import (
	"crypto"
	"testing"
)

// NewMLDSAKey returns an ML-DSA key for the named parameter set (one of
// MLDSAParameters). On Go versions before 1.27 it skips the test.
func NewMLDSAKey(tb testing.TB, _ string) crypto.Signer {
	tb.Helper()
	tb.Skip("ML-DSA requires Go 1.27 or later")
	return nil
}

// MLDSAParameterSet returns the parameter set name of an ML-DSA public or
// private key, and false for any other key.
func MLDSAParameterSet(any) (string, bool) {
	return "", false
}
