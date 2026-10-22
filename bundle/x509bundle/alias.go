// Package x509bundle provides X.509 bundle related functionality.
//
// The implementation lives in
// [github.com/spiffe/go-spiffe/lite/bundle/x509bundle].
// This package re-exports it so that existing importers of
// github.com/spiffe/go-spiffe/v2 continue to work unchanged. See that
// package for full documentation.
package x509bundle

import lite "github.com/spiffe/go-spiffe/lite/bundle/x509bundle"

// Type aliases. These must be aliases rather than definitions so that values
// cross the module boundary and interface satisfaction is preserved.
type (
	// Bundle is a collection of trusted X.509 authorities for a trust domain.
	Bundle = lite.Bundle

	// Set is a set of bundles, keyed by trust domain.
	Set = lite.Set

	// Source represents a source of X.509 bundles keyed by trust domain.
	Source = lite.Source
)

var (
	// FromX509Authorities creates a bundle from X.509 certificates.
	FromX509Authorities = lite.FromX509Authorities

	// Load loads a bundle from a file on disk. The file must contain PEM-encoded certificate blocks.
	Load = lite.Load

	// New creates a new bundle.
	New = lite.New

	// NewSet creates a new set initialized with the given bundles.
	NewSet = lite.NewSet

	// Parse parses a bundle from bytes. The data must be PEM-encoded certificate blocks.
	Parse = lite.Parse

	// ParseRaw parses a bundle from bytes. The certificate must be ASN.1 DER (concatenated with no intermediate padding if there are more than one certificate)
	ParseRaw = lite.ParseRaw

	// Read decodes a bundle from a reader. The contents must be PEM-encoded certificate blocks.
	Read = lite.Read
)
