//go:build windows
// +build windows

package workloadapi

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"
)

var (
	ErrInvalidEndpointScheme = errors.New("workload endpoint socket URI must have the scheme npipe://")
)

func parseTargetFromURLAddr(u *url.URL) (string, error) {
	switch u.Scheme {
	case "npipe":
		switch {
		case u.Opaque != "":
			return "", errors.New("workload endpoint named pipe URI must not be opaque")
		case u.User != nil:
			return "", errors.New("workload endpoint named pipe URI must not include user info")
		case u.Host != "":
			return "", errors.New("workload endpoint named pipe URI must not include a host")
		case u.Path == "":
			return "", errors.New("workload endpoint named pipe URI must include a path")
		case u.RawQuery != "":
			return "", errors.New("workload endpoint named pipe URI must not include query values")
		case u.Fragment != "":
			return "", errors.New("workload endpoint named pipe URI must not include a fragment")
		}

		if !strings.HasPrefix(filepath.ToSlash(u.Path), "//./pipe/") {
			return "", errors.New("workload endpoint named pipe URI has an invalid path")
		}
		return u.Path, nil
	default:
		return "", ErrInvalidEndpointScheme
	}
}
