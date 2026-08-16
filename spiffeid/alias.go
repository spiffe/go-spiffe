// Package spiffeid provides types and functions for SPIFFE ID and trust domain handling.
//
// The implementation lives in
// [github.com/spiffe/go-spiffe/lite/spiffeid].
// This package re-exports it so that existing importers of
// github.com/spiffe/go-spiffe/v2 continue to work unchanged. See that
// package for full documentation.
package spiffeid

import lite "github.com/spiffe/go-spiffe/lite/spiffeid"

// Type aliases. These must be aliases rather than definitions so that values
// cross the module boundary and interface satisfaction is preserved.
type (
	// ID is a SPIFFE ID
	ID = lite.ID

	// Matcher is used to match a SPIFFE ID.
	Matcher = lite.Matcher

	// TrustDomain represents the trust domain portion of a SPIFFE ID (e.g. example.org).
	TrustDomain = lite.TrustDomain
)

var (
	// FormatPath builds a path by formatting the given formatting string with the given args (i.e. fmt.Sprintf). The resulting path must be valid or an error is returned.
	FormatPath = lite.FormatPath

	// FromPath returns a new SPIFFE ID in the given trust domain and with the given path. The supplied path must be a valid absolute path according to the SPIFFE specification. See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
	FromPath = lite.FromPath

	// FromSegments returns a new SPIFFE ID in the given trust domain with joined path segments. The path segments must be valid according to the SPIFFE specification and must not contain path separators. See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
	FromSegments = lite.FromSegments

	// FromString parses a SPIFFE ID from a string.
	FromString = lite.FromString

	// FromURI parses a SPIFFE ID from a URI.
	FromURI = lite.FromURI

	// JoinPathSegments joins one or more path segments into a slash separated path. Segments cannot contain slashes. The resulting path must be valid or an error is returned. If no segments are provided, an empty string is returned.
	JoinPathSegments = lite.JoinPathSegments

	// MatchAny matches any SPIFFE ID.
	MatchAny = lite.MatchAny

	// MatchID matches a specific SPIFFE ID.
	MatchID = lite.MatchID

	// MatchMemberOf matches any SPIFFE ID in the given trust domain.
	MatchMemberOf = lite.MatchMemberOf

	// MatchOneOf matches any SPIFFE ID in the given list of IDs.
	MatchOneOf = lite.MatchOneOf

	// RequireFormatPath builds a path by formatting the given formatting string with the given args (i.e. fmt.Sprintf). The resulting path must be valid or the function panics. It should only be used when the input is statically verifiable.
	RequireFormatPath = lite.RequireFormatPath

	// RequireFromPath is similar to FromPath except that instead of returning an error on malformed input, it panics. It should only be used when the input is statically verifiable.
	RequireFromPath = lite.RequireFromPath

	// RequireFromSegments is similar to FromSegments except that instead of returning an error on malformed input, it panics. It should only be used when the input is statically verifiable.
	RequireFromSegments = lite.RequireFromSegments

	// RequireFromString is similar to FromString except that instead of returning an error on malformed input, it panics. It should only be used when the input is statically verifiable.
	RequireFromString = lite.RequireFromString

	// RequireFromURI is similar to FromURI except that instead of returning an error on malformed input, it panics. It should only be used when the input is statically verifiable.
	RequireFromURI = lite.RequireFromURI

	// RequireJoinPathSegments joins one or more path segments into a slash separated path. Segments cannot contain slashes. The resulting path must be valid or the function panics. It should only be used when the input is statically verifiable.
	RequireJoinPathSegments = lite.RequireJoinPathSegments

	// RequireTrustDomainFromString is similar to TrustDomainFromString except that instead of returning an error on malformed input, it panics. It should only be used when the input is statically verifiable.
	RequireTrustDomainFromString = lite.RequireTrustDomainFromString

	// RequireTrustDomainFromURI is similar to TrustDomainFromURI except that instead of returning an error on malformed input, it panics. It should only be used when the input is statically verifiable.
	RequireTrustDomainFromURI = lite.RequireTrustDomainFromURI

	// TrustDomainFromString returns a new TrustDomain from a string. The string can either be a trust domain name (e.g. example.org), or a valid SPIFFE ID URI (e.g. spiffe://example.org), otherwise an error is returned. See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#21-trust-domain.
	TrustDomainFromString = lite.TrustDomainFromString

	// TrustDomainFromURI returns a new TrustDomain from a URI. The URI must be a valid SPIFFE ID (see FromURI) or an error is returned. The trust domain is extracted from the host field.
	TrustDomainFromURI = lite.TrustDomainFromURI

	// ValidatePath validates that a path string is a conformant path for a SPIFFE ID. See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
	ValidatePath = lite.ValidatePath

	// ValidatePathSegment validates that a string is a conformant segment for inclusion in the path for a SPIFFE ID. See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
	ValidatePathSegment = lite.ValidatePathSegment
)

// FromPathf returns a new SPIFFE ID from the formatted path in the given trust domain. The formatted path must be a valid absolute path according to the SPIFFE specification. See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
//
// This is a function rather than a variable so that go vet's printf
// analyzer still recognizes it as a printf wrapper.
func FromPathf(td TrustDomain, format string, args ...interface{}) (ID, error) {
	return lite.FromPathf(td, format, args...)
}

// FromStringf parses a SPIFFE ID from a formatted string.
//
// This is a function rather than a variable so that go vet's printf
// analyzer still recognizes it as a printf wrapper.
func FromStringf(format string, args ...interface{}) (ID, error) {
	return lite.FromStringf(format, args...)
}

// RequireFromPathf is similar to FromPathf except that instead of returning an error on malformed input, it panics. It should only be used when the input is statically verifiable.
//
// This is a function rather than a variable so that go vet's printf
// analyzer still recognizes it as a printf wrapper.
func RequireFromPathf(td TrustDomain, format string, args ...interface{}) ID {
	return lite.RequireFromPathf(td, format, args...)
}

// RequireFromStringf is similar to FromStringf except that instead of returning an error on malformed input, it panics. It should only be used when the input is statically verifiable.
//
// This is a function rather than a variable so that go vet's printf
// analyzer still recognizes it as a printf wrapper.
func RequireFromStringf(format string, args ...interface{}) ID {
	return lite.RequireFromStringf(format, args...)
}
