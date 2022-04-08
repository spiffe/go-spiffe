//go:build !windows
// +build !windows

package workloadapi

import (
	"errors"
	"net"
	"net/url"
)

var (
	errInvalidScheme = errors.New("workload endpoint socket URI must have a tcp:// or unix:// scheme")
)

func parseTargetFromURLAddr(u *url.URL) (string, error) {
	switch u.Scheme {
	case "unix":
		switch {
		case u.Opaque != "":
			return "", errors.New("workload endpoint unix socket URI must not be opaque")
		case u.User != nil:
			return "", errors.New("workload endpoint unix socket URI must not include user info")
		case u.Host == "" && u.Path == "":
			return "", errors.New("workload endpoint unix socket URI must include a path")
		case u.RawQuery != "":
			return "", errors.New("workload endpoint unix socket URI must not include query values")
		case u.Fragment != "":
			return "", errors.New("workload endpoint unix socket URI must not include a fragment")
		}
		return u.String(), nil
	case "tcp":
		switch {
		case u.Opaque != "":
			return "", errors.New("workload endpoint tcp socket URI must not be opaque")
		case u.User != nil:
			return "", errors.New("workload endpoint tcp socket URI must not include user info")
		case u.Host == "":
			return "", errors.New("workload endpoint tcp socket URI must include a host")
		case u.Path != "":
			return "", errors.New("workload endpoint tcp socket URI must not include a path")
		case u.RawQuery != "":
			return "", errors.New("workload endpoint tcp socket URI must not include query values")
		case u.Fragment != "":
			return "", errors.New("workload endpoint tcp socket URI must not include a fragment")
		}

		ip := net.ParseIP(u.Hostname())
		if ip == nil {
			return "", errors.New("workload endpoint tcp socket URI host component must be an IP:port")
		}
		port := u.Port()
		if port == "" {
			return "", errors.New("workload endpoint tcp socket URI host component must include a port")
		}

		return net.JoinHostPort(ip.String(), port), nil
	default:
		return "", errInvalidScheme
	}
}
