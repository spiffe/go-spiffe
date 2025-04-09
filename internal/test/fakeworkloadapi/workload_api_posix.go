//go:build !windows
// +build !windows

package fakeworkloadapi

import (
	"fmt"
	"net"
	"testing"
)

func newListener(_ testing.TB) (net.Listener, error) {
	return net.Listen("tcp", "localhost:0")
}

func getTargetName(addr net.Addr) string {
	return fmt.Sprintf("%s://%s", addr.Network(), addr.String())
}
