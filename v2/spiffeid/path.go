package spiffeid

import (
	"fmt"
	"strings"
)

// FormatPath builds a path by formatting the given formatting string with
// the given args (i.e. fmt.Sprintf). The resulting path must be valid or
// an error is returned.
func FormatPath(format string, args ...interface{}) (string, error) {
	path := fmt.Sprintf(format, args...)
	if err := ValidatePath(path); err != nil {
		return "", err
	}
	return path, nil
}

// JoinPathSegments joins one or more path segments into a slash separated
// path. Segments cannot contain slashes. The resulting path must be valid or
// an error is returned. If no segments are provided, an empty string is
// returned.
func JoinPathSegments(segments ...string) (string, error) {
	var builder strings.Builder
	for _, segment := range segments {
		if err := validatePathSegment(segment); err != nil {
			return "", err
		}
		builder.WriteByte('/')
		builder.WriteString(segment)
	}
	return builder.String(), nil
}

// ValidatePath validates that a path string is a conformant path for a SPIFFE
// ID.
// See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
func ValidatePath(path string) error {
	if reason := validatePath(path); reason != noReason {
		return pathErr{path: path, reason: reason}
	}
	return nil
}

func validatePath(path string) errReason {
	switch {
	case path == "":
		return noReason
	case path[0] != '/':
		return noLeadingSlash
	}

	segmentStart := 0
	segmentEnd := 0
	for ; segmentEnd < len(path); segmentEnd++ {
		c := path[segmentEnd]
		if c == '/' {
			switch path[segmentStart:segmentEnd] {
			case "/":
				return emptySegment
			case "/.", "/..":
				return dotSegment
			}
			segmentStart = segmentEnd
			continue
		}
		if !isValidPathSegmentChar(c) {
			return badPathSegmentChar
		}
	}

	switch path[segmentStart:segmentEnd] {
	case "/":
		return trailingSlash
	case "/.", "/..":
		return dotSegment
	}
	return noReason
}

func validatePathSegment(segment string) error {
	if segment == "" {
		return segmentErr{segment: segment, reason: empty}
	}
	for i := 0; i < len(segment); i++ {
		if !isValidPathSegmentChar(segment[i]) {
			return segmentErr{segment: segment, reason: badPathSegmentChar}
		}
	}
	return nil
}

func isValidPathSegmentChar(c uint8) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_':
		return true
	case isBackcompatPathChar(c):
		return true
	default:
		return false
	}
}
