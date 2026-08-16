// Package spiffebundle provides SPIFFE bundle related functionality.
//
// The implementation lives in
// [github.com/spiffe/go-spiffe/lite/bundle/spiffebundle].
// This package re-exports it so that existing importers of
// github.com/spiffe/go-spiffe/v2 continue to work unchanged. See that
// package for full documentation.
package spiffebundle

import lite "github.com/spiffe/go-spiffe/lite/bundle/spiffebundle"

// Type aliases. These must be aliases rather than definitions so that values
// cross the module boundary and interface satisfaction is preserved.
type (
	// Bundle is a collection of trusted public key material for a trust domain, conforming to the SPIFFE Bundle Format as part of the SPIFFE Trust Domain and Bundle specification: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md
	Bundle = lite.Bundle

	// Set is a set of bundles, keyed by trust domain.
	Set = lite.Set

	// Source represents a source of SPIFFE bundles keyed by trust domain.
	Source = lite.Source
)

var (
	// FromJWTAuthorities creates a new bundle from JWT authorities.
	FromJWTAuthorities = lite.FromJWTAuthorities

	// FromJWTBundle creates a bundle from a JWT bundle. The function panics in case of a nil JWT bundle.
	FromJWTBundle = lite.FromJWTBundle

	// FromWITAuthorities creates a new bundle from WIT authorities.
	FromWITAuthorities = lite.FromWITAuthorities

	// FromWITBundle creates a bundle from a WIT bundle. The function panics in case of a nil WIT bundle.
	FromWITBundle = lite.FromWITBundle

	// FromX509Authorities creates a bundle from X.509 certificates.
	FromX509Authorities = lite.FromX509Authorities

	// FromX509Bundle creates a bundle from an X.509 bundle. The function panics in case of a nil X.509 bundle.
	FromX509Bundle = lite.FromX509Bundle

	// Load loads a bundle from a file on disk. The file must contain a JWKS document following the SPIFFE Trust Domain and Bundle specification.
	Load = lite.Load

	// New creates a new bundle.
	New = lite.New

	// NewSet creates a new set initialized with the given bundles.
	NewSet = lite.NewSet

	// Parse parses a bundle from bytes. The data must be a JWKS document following the SPIFFE Trust Domain and Bundle specification.
	Parse = lite.Parse

	// Read decodes a bundle from a reader. The contents must contain a JWKS document following the SPIFFE Trust Domain and Bundle specification.
	Read = lite.Read
)
