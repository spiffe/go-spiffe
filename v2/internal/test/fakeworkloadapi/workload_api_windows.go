//go:build windows
// +build windows

package fakeworkloadapi

import (
	"net"

	"github.com/Microsoft/go-winio"
)

func newListener() (net.Listener, error) {
	return winio.ListenPipe("//./pipe/spire-test", nil)
}
