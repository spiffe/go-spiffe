package jwtworkload

import (
	"context"
	"crypto"
	"errors"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffejwt"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// ErrNotReady is returned when the workload has yet to receive the initial
// response from the Workload API.
var ErrNotReady = errors.New("jwt-workload: not ready")

// ErrClosed is returned from methods that provide up-to-date information from
// the Workload API after the workload has been closed to prevent callers from
// relying on stale information.
var ErrClosed = errors.New("jwt-workload: closed")

// Workload is a JWT workload that maintains up-to-date JWT bundles
// retrieved from the Workload API as well as providing convenience methods
// for fetching and validating JWT-SVIDs
type Workload struct{}

// Open opens the JWT workload against the Workload API. It does not return
// until the workload has received the first update from the Workload API,
// unless the NoWait option is used.
func Open(ctx context.Context, options ...Option) (*Workload, error) {
	panic("not implemented")
}

// Close closes the JWT workload, tearing down streams and disconnecting
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

// FetchJWTSVID fetches a JWT-SVID. At least one audience value is required.
func (w *Workload) FetchJWTSVID(ctx context.Context, audience string, options ...workloadapi.JWTSVIDOption) (*spiffejwt.SVID, error) {
	panic("not implemented")
}

// GetJWTKey a JWT key by key id in the trust domain of the workload.
func (w *Workload) GetJWTKey(keyID string) (crypto.PublicKey, error) {
	panic("not implemented")
}

// GetJWTKeyForTrustDomain a JWT key by key id in the specified trust domain.
func (w *Workload) GetJWTKeyForTrustDomain(trustDomain spiffeid.TrustDomain, keyID string) (crypto.PublicKey, error) {
	panic("not implemented")
}
