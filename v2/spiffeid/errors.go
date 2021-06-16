package spiffeid

import "fmt"

type errReason string

const (
	noReason           errReason = ""
	badTrustDomainChar errReason = "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores"
	badPathSegmentChar errReason = "path segment characters are limited to letters, numbers, dots, dashes, and underscores"
	dotSegment         errReason = "path cannot contain dot segments"
	noLeadingSlash     errReason = "path must have a leading slash"
	empty              errReason = "cannot be empty"
	emptySegment       errReason = "path cannot contain empty segments"
	missingTrustDomain errReason = "trust domain is missing"
	trailingSlash      errReason = "path cannot have a trailing slash"
	wrongScheme        errReason = "scheme is missing or invalid"
)

type tdErr struct {
	td     string
	reason errReason
}

func (e tdErr) Error() string {
	return fmt.Sprintf("invalid trust domain %q: %s", e.td, e.reason)
}

type idErr struct {
	id     string
	reason errReason
}

func (e idErr) Error() string {
	return fmt.Sprintf("invalid SPIFFE ID %q: %s", e.id, e.reason)
}

type pathErr struct {
	path   string
	reason errReason
}

func (e pathErr) Error() string {
	return fmt.Sprintf("invalid path %q: %s", e.path, e.reason)
}

type segmentErr struct {
	segment string
	reason  errReason
}

func (e segmentErr) Error() string {
	return fmt.Sprintf("invalid path segment %q: %s", e.segment, e.reason)
}
