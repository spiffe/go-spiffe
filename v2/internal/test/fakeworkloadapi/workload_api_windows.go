//go:build windows
// +build windows

package fakeworkloadapi

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"net"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var maxUint64 = maxBigUint64()

func NewWithNamedPipeListener(tb testing.TB) *WorkloadAPI {
	w := &WorkloadAPI{
		x509Chans:       make(map[chan *workload.X509SVIDResponse]struct{}),
		jwtBundlesChans: make(map[chan *workload.JWTBundlesResponse]struct{}),
	}

	listener, err := winio.ListenPipe(fmt.Sprintf(`\\.\pipe\go-spiffe-test-pipe-%x`, randUint64(tb)), nil)
	require.NoError(tb, err)

	server := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(server, &workloadAPIWrapper{w: w})

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		_ = server.Serve(listener)
	}()

	w.addr = getTargetName(listener.Addr())
	tb.Logf("WorkloadAPI address: %s", w.addr)
	w.server = server
	return w
}

func GetPipeName(s string) string {
	return strings.TrimPrefix(s, `\\.\pipe`)
}

func maxBigUint64() *big.Int {
	n := big.NewInt(0)
	return n.SetUint64(math.MaxUint64)
}

func randUint64(t testing.TB) uint64 {
	n, err := rand.Int(rand.Reader, maxUint64)
	if err != nil {
		t.Fail()
	}

	return n.Uint64()
}

func newListener(tb testing.TB) (net.Listener, error) {
	return winio.ListenPipe(fmt.Sprintf(`\\.\pipe\go-spiffe-test-pipe-%x`, randUint64(tb)), nil)
}

func getTargetName(addr net.Addr) string {
	if addr.Network() == "pipe" {
		// The go-winio library defines the network of a
		// named pipe address as "pipe", but we use the
		// "npipe" scheme for named pipes URLs.
		return "npipe:" + GetPipeName(addr.String())
	}

	return fmt.Sprintf("%s://%s", addr.Network(), addr.String())
}
