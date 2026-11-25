package cryptoutil

import (
	"crypto"
	"fmt"
)

func PublicKeyEqual(a, b crypto.PublicKey) (bool, error) {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false, fmt.Errorf("unsupported public key type %T", a)
	}
	return k.Equal(b), nil
}
