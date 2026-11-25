package brokerapi

import (
	"errors"
	"net"
	"net/url"
	"os"
)

const (
	// SocketEnv is the environment variable holding the default Broker API
	// address.
	SocketEnv = "SPIFFE_BROKER_SOCKET"
)

// ErrInvalidEndpointScheme indicates that the Broker API endpoint address has
// an unsupported URI scheme.
var ErrInvalidEndpointScheme = errors.New(`broker endpoint socket URI must have a "tcp" or "unix" scheme`)

// GetDefaultAddress returns the default Broker API address from the
// environment.
//
// Experimental: subject to change.
func GetDefaultAddress() (string, bool) {
	return os.LookupEnv(SocketEnv)
}

// ValidateAddress validates that the provided address can be parsed to a gRPC
// target string for dialing a Broker API endpoint exposed as either a Unix
// Domain Socket or TCP socket.
//
// Experimental: subject to change.
func ValidateAddress(addr string) error {
	_, err := TargetFromAddress(addr)
	return err
}

// TargetFromAddress parses the Broker API endpoint address and returns a gRPC
// target string for dialing.
//
// Experimental: subject to change.
func TargetFromAddress(addr string) (string, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return "", errors.New("broker endpoint socket is not a valid URI: " + err.Error())
	}

	switch u.Scheme {
	case "tcp":
		return parseTCPTarget(u)
	case "unix":
		return parseUnixTarget(u)
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
