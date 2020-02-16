package bundleworkload

import (
	"context"
	"errors"

	"github.com/spiffe/go-spiffe/v2/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// ErrNotReady is returned when the workload has yet to receive the initial
// response from the Workload API.
var ErrNotReady = errors.New("bundle-workload: not ready")

// ErrClosed is returned from methods that provide up-to-date information from
// the Workload API after the workload has been closed to prevent callers from
// relying on stale information.
var ErrClosed = errors.New("bundle-workload: closed")

// Workload is a bundle workload that maintains up-to-date bundle information
// retrieved from the Workload API.
type Workload struct{}

// Open opens the bundle workload against the Workload API. It does not return
// until the workload has received the first update from the Workload API,
// unless the NoWait option is used.
func Open(ctx context.Context, options ...Option) (*Workload, error) {
	panic("not implemented")
}

// Close closes the bundle workload, tearing down streams and disconnecting
// from the workload API. Other methods that rely on up-to-date information
// from the workload API will fail with ErrClosed after this call to prevent
// callers from relying on stale information.
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

// GetBundleForTrustDomain gets the bundle for the given trust domain
func (w *Workload) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*spiffebundle.Bundle, error) {
	panic("not implemented")
}
