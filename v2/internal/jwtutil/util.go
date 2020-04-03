package jwtutil

import (
	"crypto"

	"github.com/spiffe/go-spiffe/v2/internal/cryptoutil"
)

// CopyJWTKeys copies JWT public keys from a map to a new map.
func CopyJWTKeys(jwtKeys map[string]crypto.PublicKey) map[string]crypto.PublicKey {
	copiedJWTKeys := make(map[string]crypto.PublicKey)
	for key, jwtKey := range jwtKeys {
		copiedJWTKeys[key] = jwtKey
	}
	return copiedJWTKeys
}

func JWTKeysEqual(a, b map[string]crypto.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}

	for k, pka := range a {
		pkb, ok := b[k]
		if !ok {
			return false
		}
		if equal, _ := cryptoutil.PublicKeyEqual(pka, pkb); !equal {
			return false
		}
	}

	return true
}
