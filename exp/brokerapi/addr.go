package brokerapi

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	// SocketEnv is the environment variable holding the default Broker API
	// address.
	SocketEnv = "SPIFFE_BROKER_SOCKET"
)

// ErrInvalidEndpointScheme indicates that the Broker API endpoint address has
// an unsupported URI scheme.
var ErrInvalidEndpointScheme = errors.New(`broker endpoint socket URI must have a "tcp", "unix", or "dns" scheme`)

// GetDefaultAddress returns the default Broker API address from the
// environment.
//
// Experimental: subject to change.
func GetDefaultAddress() (string, bool) {
	return os.LookupEnv(SocketEnv)
}

// ValidateAddress validates that the provided address can be parsed to a gRPC
// target string for dialing a Broker API endpoint exposed as a Unix Domain
// Socket or TCP socket, already expressed as a DNS target, or given as a bare
// host:port address.
//
// Experimental: subject to change.
func ValidateAddress(addr string) error {
	_, err := TargetFromAddress(addr)
	return err
}

// TargetFromAddress parses the Broker API endpoint address and returns a gRPC
// target string for dialing. In addition to "tcp" and "unix" addresses, a gRPC
// "dns" target address is accepted. A bare host:port address is treated as a
// DNS target.
//
// Experimental: subject to change.
func TargetFromAddress(addr string) (string, error) {
	if !strings.Contains(addr, "://") {
		if target, ok := parseBareTarget(addr); ok {
			return target, nil
		}
	}

	u, err := url.Parse(addr)
	if err != nil {
		return "", errors.New("broker endpoint socket is not a valid URI: " + err.Error())
	}

	switch u.Scheme {
	case "tcp":
		return parseTCPTarget(u)
	case "unix":
		return parseUnixTarget(u)
	case "dns":
		return parseDNSTarget(u)
	default:
		return "", ErrInvalidEndpointScheme
	}
}

func parseTCPTarget(u *url.URL) (string, error) {
	switch {
	case u.Opaque != "":
		return "", errors.New("broker endpoint tcp socket URI must not be opaque")
	case u.User != nil:
		return "", errors.New("broker endpoint tcp socket URI must not include user info")
	case u.Host == "":
		return "", errors.New("broker endpoint tcp socket URI must include a host")
	case u.Path != "":
		return "", errors.New("broker endpoint tcp socket URI must not include a path")
	case u.RawQuery != "":
		return "", errors.New("broker endpoint tcp socket URI must not include query values")
	case u.Fragment != "":
		return "", errors.New("broker endpoint tcp socket URI must not include a fragment")
	}

	host := u.Hostname()
	if host == "" {
		return "", errors.New("broker endpoint tcp socket URI host component must include a hostname or IP")
	}
	port := u.Port()
	if port == "" {
		return "", errors.New("broker endpoint tcp socket URI host component must include a port")
	}

	return "dns:///" + net.JoinHostPort(host, port), nil
}

func parseBareTarget(addr string) (string, bool) {
	if scheme, _, ok := strings.Cut(addr, ":"); ok {
		switch scheme {
		case "tcp", "unix", "dns":
			return "", false
		}
	}
	if strings.ContainsAny(addr, "/?#@") {
		return "", false
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return "", false
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", false
	}

	return "dns:///" + net.JoinHostPort(host, port), true
}

func parseDNSTarget(u *url.URL) (string, error) {
	switch {
	case u.Opaque != "":
		return "", errors.New("broker endpoint dns URI must not be opaque")
	case u.User != nil:
		return "", errors.New("broker endpoint dns URI must not include user info")
	case u.RawQuery != "":
		return "", errors.New("broker endpoint dns URI must not include query values")
	case u.Fragment != "":
		return "", errors.New("broker endpoint dns URI must not include a fragment")
	}

	var endpoint string
	switch {
	case u.Host != "":
		if u.Path != "" {
			return "", errors.New("broker endpoint dns URI must not include a path")
		}
		endpoint = u.Host
	case strings.HasPrefix(u.Path, "/"):
		endpoint = strings.TrimPrefix(u.Path, "/")
		if endpoint == "" || strings.Contains(endpoint, "/") {
			return "", errors.New("broker endpoint dns URI host component must include a hostname or IP and a port")
		}
	default:
		return "", errors.New("broker endpoint dns URI must include a host")
	}

	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", errors.New("broker endpoint dns URI host component must include a hostname or IP and a port")
	}
	if host == "" {
		return "", errors.New("broker endpoint dns URI host component must include a hostname or IP")
	}
	if port == "" {
		return "", errors.New("broker endpoint dns URI host component must include a port")
	}

	return "dns:///" + net.JoinHostPort(host, port), nil
}

func parseUnixTarget(u *url.URL) (string, error) {
	switch {
	case u.Opaque != "":
		return "", errors.New("broker endpoint unix socket URI must not be opaque")
	case u.User != nil:
		return "", errors.New("broker endpoint unix socket URI must not include user info")
	case u.Host != "":
		return "", errors.New("broker endpoint unix socket URI must not include an authority")
	case u.Path == "":
		return "", errors.New("broker endpoint unix socket URI must include a path")
	case u.RawQuery != "":
		return "", errors.New("broker endpoint unix socket URI must not include query values")
	case u.Fragment != "":
		return "", errors.New("broker endpoint unix socket URI must not include a fragment")
	}

	return u.String(), nil
}
