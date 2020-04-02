package jwtutil

import (
	"crypto"
)

// CopyJWTKeys copies JWT public keys from a map to a new map.
func CopyJWTKeys(jwtKeys map[string]crypto.PublicKey) map[string]crypto.PublicKey {
	copiedJWTKeys := make(map[string]crypto.PublicKey)
	for key, jwtKey := range jwtKeys {
		copiedJWTKeys[key] = jwtKey
	}
	return copiedJWTKeys
}
