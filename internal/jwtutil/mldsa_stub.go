//go:build !go1.27

package jwtutil

// mldsaSupported tells whether go-jose decodes ML-DSA keys, which it only
// does when built with Go 1.27 or later.
const mldsaSupported = false
