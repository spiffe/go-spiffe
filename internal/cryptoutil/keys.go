package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"fmt"
)

func PublicKeyEqual(a, b crypto.PublicKey) (bool, error) {
	switch a := a.(type) {
	case *rsa.PublicKey:
		return a.Equal(b), nil
	case *ecdsa.PublicKey:
		return a.Equal(b), nil
	case ed25519.PublicKey:
		return a.Equal(b), nil
	case *mldsa.PublicKey:
		return a.Equal(b), nil
	default:
		return false, fmt.Errorf("unsupported public key type %T", a)
	}
}
