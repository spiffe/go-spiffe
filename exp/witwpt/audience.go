package witwpt

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// AudienceMatcher decides whether a WPT's aud claim is acceptable for this
// request. It is called with the aud claim exactly as it appeared in the proof.
type AudienceMatcher func(aud string) error

// AcceptAudience returns an AudienceMatcher that matches aud against values,
// normalizing both sides to scheme and authority as wpt-01 §2's "acceptable
// alias or normalization" allows: the scheme and host are lowercased, and a
// default port, path, query, and fragment are dropped.
//
// Dropping the path means a proof is bound to an authority, not to a route, so
// any endpoint on that hostname accepts a captured pair for the proof's
// lifetime; WithReplayCache narrows that, a path in a configured value does not.
//
// A value that cannot be normalized is kept verbatim, so it never matches and
// still appears in the mismatch error.
func AcceptAudience(values ...string) AudienceMatcher {
	accepted := make([]string, 0, len(values))
	for _, value := range values {
		normalized, err := normalizeAudience(value)
		if err != nil {
			normalized = value
		}
		accepted = append(accepted, normalized)
	}

	return func(aud string) error {
		if aud == "" {
			return wrapErr(errors.New("proof is missing the aud claim"))
		}

		normalized, err := normalizeAudience(aud)
		if err != nil {
			return wrapErr(fmt.Errorf("proof audience %q is not a valid absolute URI", aud))
		}

		for _, candidate := range accepted {
			if normalized == candidate {
				return nil
			}
		}

		// Both sides are named so a proxy or port misconfiguration is diagnosable
		// from one log line.
		return wrapErr(fmt.Errorf("proof audience %q is not accepted here (expected one of %q)",
			aud, accepted))
	}
}

// normalizeAudience reduces an absolute URI to scheme://authority, dropping the
// default port for the scheme along with any path, query, and fragment.
func normalizeAudience(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("not an absolute URI: %q", value)
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("no host in %q", value)
	}

	if port := parsed.Port(); port != "" && !isDefaultPort(scheme, port) {
		host = host + ":" + port
	}
	return scheme + "://" + host, nil
}

func isDefaultPort(scheme, port string) bool {
	switch scheme {
	case "https":
		return port == "443"
	case "http":
		return port == "80"
	default:
		return false
	}
}

func wrapErr(err error) error {
	return fmt.Errorf("witwpt: %w", err)
}
