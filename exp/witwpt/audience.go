package witwpt

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// AudienceMatcher decides whether a WPT's aud claim is acceptable for this
// request. It is called with the aud claim exactly as it appeared in the proof.
type AudienceMatcher func(aud string) error

// AcceptAudience returns an AudienceMatcher that matches aud against values,
// normalizing both sides to scheme and authority as wpt-01 §2's "acceptable
// alias or normalization" allows: scheme and host are lowercased, and a default
// port, path, query, and fragment are dropped. A proof is therefore bound to an
// authority, not to a route; a path in a configured value is ignored.
//
// It returns an error if values is empty or any value is not an absolute URI
// without userinfo.
func AcceptAudience(values ...string) (AudienceMatcher, error) {
	if len(values) == 0 {
		return nil, wrapErr(errors.New("no audiences provided"))
	}
	accepted := make([]string, 0, len(values))
	for _, value := range values {
		normalized, err := normalizeAudience(value)
		if err != nil {
			return nil, wrapErr(fmt.Errorf("audience %q is not a valid absolute URI", value))
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
	}, nil
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
	if parsed.User != nil {
		return "", fmt.Errorf("userinfo in %q", value)
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("no host in %q", value)
	}

	// Hostname strips IPv6 brackets, which must be restored or "[::1]:8443"
	// and "[::1:8443]" normalize to the same string.
	if port := parsed.Port(); port != "" && !isDefaultPort(scheme, port) {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
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
