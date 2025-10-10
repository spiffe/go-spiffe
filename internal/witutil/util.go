package witutil

import (
	"crypto"

	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
)

// CopyWITAuthorities copies WIT authoritiies from a map to a new map. Note: this shared the jwtutil implementation
func CopyWITAuthorities(witAuthorities map[string]crypto.PublicKey) map[string]crypto.PublicKey {
	return jwtutil.CopyJWTAuthorities(witAuthorities)
}

func WITAuthoritiesEqual(a, b map[string]crypto.PublicKey) bool {
	return jwtutil.JWTAuthoritiesEqual(a, b)
}
