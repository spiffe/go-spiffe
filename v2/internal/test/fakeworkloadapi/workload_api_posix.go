//go:build !windows
// +build !windows

package fakeworkloadapi

import (
	"net"
)

func newListener() (net.Listener, error) {
	return net.Listen("tcp", "localhost:0")
}
