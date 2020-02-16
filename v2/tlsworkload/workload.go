package tlsworkload

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffex509"
)

// ErrNotReady is returned when the workload has yet to receive the initial
// response from the Workload API.
var ErrNotReady = errors.New("tls-workload: not ready")

// ErrClosed is returned from methods that provide up-to-date information from
// the Workload API after the workload has been closed to prevent callers from
// relying on stale information.
var ErrClosed = errors.New("tls-workload: closed")

// Workload is a TLS workload that maintains up-to-date TLS context (i.e.
// SVIDs with private keys, trusted X.509 roots, etc.) retrieved from the
// Workload API.
type Workload struct{}

// Open opens the TLS workload against the Workload API. It does not return
// until the workload has received the first update from the Workload API,
// unless the NoWait option is used.
func Open(ctx context.Context, options ...Option) (*Workload, error) {
	panic("not implemented")
}

// Close closes the TLS workload, tearing down streams and disconnecting
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

// GetX509SVID returns the default X509-SVID for the workload. If the workload
// is not ready, it will return ErrNotReady.
func (w *Workload) GetX509SVID() (*spiffex509.SVID, error) {
	panic("not implemented")
}

// GetX509SVIDs returns all X509-SVIDs for the workload. If the workload
// is not ready, it will return ErrNotReady.
func (w *Workload) GetX509SVIDs() ([]*spiffex509.SVID, error) {
	panic("not implemented")
}

// GetX509Roots returns the X.509 roots for the trust domain of the workload.
// If the workload is not ready, it will return ErrNotReady.
func (w *Workload) GetX509Roots() ([]*x509.Certificate, error) {
	panic("not implemented")
}

// GetX509RootsForTrustDomain returns the root certificates for the specified
// trust domain.  If the workload is not ready, it will return ErrNotReady.
func (w *Workload) GetX509RootsForTrustDomain(trustDomain spiffeid.TrustDomain) ([]*x509.Certificate, error) {
	panic("not implemented")
}
