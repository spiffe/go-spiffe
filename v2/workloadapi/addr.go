package workloadapi

import (
	"errors"
	"net/url"
	"os"
)

const (
	// SocketEnv is the environment variable holding the default Workload API
	// address.
	SocketEnv = "SPIFFE_ENDPOINT_SOCKET"
)

func GetDefaultAddress() (string, bool) {
	return os.LookupEnv(SocketEnv)
}

func ValidateAddress(addr string) error {
	_, err := parseTargetFromStringAddr(addr)
	return err
}

// parseTargetFromStringAddr parses the endpoint address and returns a gRPC target
// string for dialing.
func parseTargetFromStringAddr(addr string) (string, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return "", errors.New("workload endpoint socket is not a valid URI: " + err.Error())
	}
	return parseTargetFromURLAddr(u)
}
