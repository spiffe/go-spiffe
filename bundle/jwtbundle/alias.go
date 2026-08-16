// Package jwtbundle provides JWT bundle related functionality.
//
// The implementation lives in
// [github.com/spiffe/go-spiffe/lite/bundle/jwtbundle].
// This package re-exports it so that existing importers of
// github.com/spiffe/go-spiffe/v2 continue to work unchanged. See that
// package for full documentation.
package jwtbundle

import lite "github.com/spiffe/go-spiffe/lite/bundle/jwtbundle"

// Type aliases. These must be aliases rather than definitions so that values
// cross the module boundary and interface satisfaction is preserved.
type (
	// Bundle is a collection of trusted JWT authorities for a trust domain.
	Bundle = lite.Bundle

	// Set is a set of bundles, keyed by trust domain.
	Set = lite.Set

	// Source represents a source of JWT bundles keyed by trust domain.
	Source = lite.Source
)

var (
	// FromJWTAuthorities creates a new bundle from JWT authorities
	FromJWTAuthorities = lite.FromJWTAuthorities

	// Load loads a bundle from a file on disk. The file must contain a standard RFC 7517 JWKS document.
	Load = lite.Load

	// New creates a new bundle.
	New = lite.New

	// NewSet creates a new set initialized with the given bundles.
	NewSet = lite.NewSet

	// Parse parses a bundle from bytes. The data must be a standard RFC 7517 JWKS document.
	Parse = lite.Parse

	// Read decodes a bundle from a reader. The contents must contain a standard RFC 7517 JWKS document.
	Read = lite.Read
)
