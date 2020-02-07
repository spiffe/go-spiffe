package bundleworkload

import (
	"context"
	"errors"

	"github.com/spiffe/go-spiffe/v2/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var ErrNotReady = errors.New("bundle-workload: not ready")

type Workload struct{}

// Open opens the TLS workload against the Workload API. It does not return
// until the workload has received the first update from the Workload API,
// unless the NoWait option is used.
func Open(ctx context.Context, options ...Option) (*Workload, error) {
	panic("not implemented")
}

func (w *Workload) Close() error {
	panic("not implemented")
}

// WaitUntilReady waits until the workload is ready or the context is canceled,
// which causes the method to return ctx.Err(). WaitUntilReady will also
// return an error if the workload is closed.
func (w *Workload) WaitUntilReady(ctx context.Context) error {
	panic("not implemented")
}

// GetBundle gets the bundle for the trust domain of the workload
func (w *Workload) GetBundle() (*spiffebundle.Bundle, error) {
	panic("not implemented")
}

// GetBundleForTrustDomain gets the bundle for the spcified trust domain
func (w *Workload) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*spiffebundle.Bundle, error) {
	panic("not implemented")
}
