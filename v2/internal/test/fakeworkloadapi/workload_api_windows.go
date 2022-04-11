//go:build windows
// +build windows

package fakeworkloadapi

import (
	"fmt"
	"math/rand"
	"net"

	"github.com/Microsoft/go-winio"
)

func newListener() (net.Listener, error) {
	pipeName := fmt.Sprintf(`//./pipe/go-spiffe-test-pipe-%x`, rand.Uint64())
	return winio.ListenPipe(pipeName, nil)
}
