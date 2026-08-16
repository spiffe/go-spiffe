// Package witsvid provides WIT-SVID related functionality.
//
// The implementation lives in
// [github.com/spiffe/go-spiffe/lite/exp/svid/witsvid].
// This package re-exports it so that existing importers of
// github.com/spiffe/go-spiffe/v2 continue to work unchanged. See that
// package for full documentation.
package witsvid

import lite "github.com/spiffe/go-spiffe/lite/exp/svid/witsvid"

// Type aliases. These must be aliases rather than definitions so that values
// cross the module boundary and interface satisfaction is preserved.
type (
	// SVID represents a WIT-SVID.
	SVID = lite.SVID

	// Source is a source of WIT-SVIDs keyed by SPIFFE ID.
	Source = lite.Source
)

var (
	// ParseAndValidate parses and validates a WIT-SVID token, verifying its signature using the provided WIT bundle source.
	ParseAndValidate = lite.ParseAndValidate

	// ParseInsecure parses a WIT-SVID token without verifying its signature. This should only be used when the token was received from a trusted source (e.g., the Workload API).
	ParseInsecure = lite.ParseInsecure
)
