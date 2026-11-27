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

// AcceptAudience returns an AudienceMatcher accepting any of values. Both sides
// are reduced to lowercase scheme://authority without a default port, so a proof
// is bound to a host, not a route. values must be http or https URIs without userinfo.
func AcceptAudience(values ...string) (AudienceMatcher, error) {
	return acceptAudience(values, false)
}

// AcceptTargetURI is AcceptAudience that also requires the path to match, so a
// proof is bound to one route. Query and fragment are ignored (wpt-02 §2). It
// does not suit a service behind a proxy that rewrites paths.
func AcceptTargetURI(values ...string) (AudienceMatcher, error) {
	return acceptAudience(values, true)
}

func acceptAudience(values []string, withPath bool) (AudienceMatcher, error) {
	if len(values) == 0 {
		return nil, wrapErr(errors.New("no audiences provided"))
	}
	accepted := make([]string, 0, len(values))
	for _, value := range values {
		normalized, err := normalizeAudience(value, withPath)
		if err != nil {
			return nil, wrapErr(fmt.Errorf("audience %q is not an absolute http(s) URI", value))
		}
		accepted = append(accepted, normalized)
	}

	return func(aud string) error {
		normalized, err := normalizeAudience(aud, withPath)
		if err != nil {
			return fmt.Errorf("proof audience %q is not an absolute http(s) URI", aud)
		}

		for _, candidate := range accepted {
			if normalized == candidate {
				return nil
			}
		}

		// Both sides are named so a proxy or port misconfiguration is diagnosable
		// from one log line.
		return fmt.Errorf("proof audience %q is not accepted here (expected one of %q)",
			aud, accepted)
	}, nil
}

// normalizeAudience reduces an absolute URI to scheme://authority, followed by
// its escaped path when withPath is set.
func normalizeAudience(value string, withPath bool) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}

	// Other schemes, such as spiffe, would lose their path and collapse to the
	// trust domain.
	scheme := strings.ToLower(parsed.Scheme)
	if (scheme != "https" && scheme != "http") || parsed.Host == "" {
		return "", fmt.Errorf("not an absolute http(s) URI: %q", value)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("userinfo in %q", value)
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("no host in %q", value)
	}

	// Hostname strips IPv6 brackets; restore them to keep the authority unambiguous.
	if port := parsed.Port(); port != "" && !isDefaultPort(scheme, port) {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	normalized := scheme + "://" + host
	if withPath {
		// An empty path and "/" name the same resource (RFC 9110 §4.2.3).
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		normalized += path
	}
	return normalized, nil
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
