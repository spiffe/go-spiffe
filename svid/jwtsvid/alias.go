// Package jwtsvid provides JWT-SVID related functionality.
//
// The implementation lives in
// [github.com/spiffe/go-spiffe/lite/svid/jwtsvid].
// This package re-exports it so that existing importers of
// github.com/spiffe/go-spiffe/v2 continue to work unchanged. See that
// package for full documentation.
package jwtsvid

import lite "github.com/spiffe/go-spiffe/lite/svid/jwtsvid"

// Type aliases. These must be aliases rather than definitions so that values
// cross the module boundary and interface satisfaction is preserved.
type (
	// Params are JWT-SVID parameters used when fetching a new JWT-SVID.
	Params = lite.Params

	// SVID represents a JWT-SVID.
	SVID = lite.SVID

	// Source represents a source of JWT-SVIDs.
	Source = lite.Source
)

var (
	// ParseAndValidate parses and validates a JWT-SVID token and returns the JWT-SVID. The JWT-SVID signature is verified using the JWT bundle source.
	ParseAndValidate = lite.ParseAndValidate

	// ParseInsecure parses and validates a JWT-SVID token and returns the JWT-SVID. The JWT-SVID signature is not verified.
	ParseInsecure = lite.ParseInsecure
)
