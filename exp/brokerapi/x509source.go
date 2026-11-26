package brokerapi

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/protobuf/proto"
)

// X509Source is a source of X509-SVIDs and X.509 bundles maintained via the
// Broker API for a specific workload reference. It implements both
// x509svid.Source and x509bundle.Source.
//
// Experimental: subject to change.
type X509Source struct {
	sourceBase

	client    *Client
	reference *brokerpb.WorkloadReference
	picker    func([]*x509svid.SVID) *x509svid.SVID

	mtx     sync.RWMutex
	svid    *x509svid.SVID
	bundles *x509bundle.Set

	x509ContextSet     chan struct{}
	x509ContextSetOnce sync.Once
}

// NewX509Source creates a new X509Source for the given workload reference. It
// blocks until the initial update has been received from the Broker API. The
// source should be closed when no longer in use.
//
// The source does not own the client. The client should be closed separately
// once all sources created from it are closed.
//
// Experimental: subject to change.
func NewX509Source(ctx context.Context, client *Client, workloadReference proto.Message, options ...X509SourceOption) (_ *X509Source, err error) {
	if err := validateClient(client); err != nil {
		return nil, err
	}

	config := &x509SourceConfig{}
	for _, option := range options {
		option.configureX509Source(config)
	}

	reference, err := newWorkloadReference(workloadReference)
	if err != nil {
		return nil, err
	}
	if err := validateReferenceScope(reference, client.config.address); err != nil {
		return nil, err
	}

	s := &X509Source{
		sourceBase:     newSourceBase(1),
		client:         client,
		reference:      reference,
		picker:         config.picker,
		bundles:        x509bundle.NewSet(),
		x509ContextSet: make(chan struct{}),
	}

	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
		}
	}()

	errCh := make(chan error, 1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		errCh <- s.watch(s.ctx)
	}()

	select {
	case <-s.x509ContextSet:
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, joinWatchError(ctx.Err(), s.lastWatchError())
	}

	s.drainUpdated()
	return s, nil
}

// NewX509Source creates a new X509Source for the given workload reference. It
// is a convenience method that calls the package-level NewX509Source.
//
// Experimental: subject to change.
func (c *Client) NewX509Source(ctx context.Context, workloadReference proto.Message, options ...X509SourceOption) (*X509Source, error) {
	return NewX509Source(ctx, c, workloadReference, options...)
}

// Close closes the source, dropping the streams to the Broker API. Other
// source methods will return an error after Close has been called.
//
// Experimental: subject to change.
func (s *X509Source) Close() error {
	return s.close()
}

// GetX509SVID returns an X509-SVID from the source. It implements the
// x509svid.Source interface.
//
// Experimental: subject to change.
func (s *X509Source) GetX509SVID() (*x509svid.SVID, error) {
	if err := s.checkClosed(); err != nil {
		return nil, wrapX509SourceErr(err)
	}

	s.mtx.RLock()
	svid := s.svid
	s.mtx.RUnlock()

	if svid == nil {
		return nil, wrapX509SourceErr(errors.New("missing X509-SVID"))
	}
	return svid, nil
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface.
//
// Experimental: subject to change.
func (s *X509Source) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, wrapX509SourceErr(err)
	}

	s.mtx.RLock()
	bundles := s.bundles
	s.mtx.RUnlock()

	if bundles == nil {
		return nil, wrapX509SourceErr(errors.New("missing X.509 bundles"))
	}
	return bundles.GetX509BundleForTrustDomain(trustDomain)
}

// WaitUntilUpdated waits until the source is updated or the context is done,
// in which case ctx.Err() is returned.
//
// Experimental: subject to change.
func (s *X509Source) WaitUntilUpdated(ctx context.Context) error {
	return s.waitUntilUpdated(ctx)
}

// Updated returns a channel that is sent on whenever the source is updated.
//
// Experimental: subject to change.
func (s *X509Source) Updated() <-chan struct{} {
	return s.updated()
}

// Done returns a channel that is closed when the source stops watching for
// updates, either because it was closed or because the watch terminated.
//
// Experimental: subject to change.
func (s *X509Source) Done() <-chan struct{} {
	return s.done()
}

// Err returns the most recent error encountered while watching for updates, or
// nil if no error has occurred.
//
// Experimental: subject to change.
func (s *X509Source) Err() error {
	return s.lastWatchError()
}

func (s *X509Source) watch(ctx context.Context) error {
	defer s.markWatchDone()
	return watch(ctx, s.client.config.log, s.client.config.backoffStrategy, "X.509-SVIDs", s.open, s.update, s.clear, s.recordWatchError)
}

func (s *X509Source) open(ctx context.Context) (recvFunc[*brokerpb.SubscribeToX509SVIDResponse], error) {
	stream, err := s.client.apiClient.SubscribeToX509SVID(ctx, &brokerpb.SubscribeToX509SVIDRequest{
		Reference: s.reference,
	})
	if err != nil {
		return nil, err
	}
	return stream.Recv, nil
}

func (s *X509Source) update(response *brokerpb.SubscribeToX509SVIDResponse) error {
	svids, bundles, err := parseX509Context(response)
	if err != nil {
		return err
	}

	var svid *x509svid.SVID
	if s.picker == nil {
		svid = svids[0]
	} else {
		svid = s.picker(svids)
		if svid == nil {
			return newWatchTerminalError(errors.New("X509-SVID picker returned nil"))
		}
	}

	s.mtx.Lock()
	s.svid = svid
	s.bundles = bundles
	s.mtx.Unlock()

	s.triggerUpdated()
	s.x509ContextSetOnce.Do(func() {
		close(s.x509ContextSet)
	})
	return nil
}

func (s *X509Source) clear() {
	s.mtx.Lock()
	s.svid = nil
	s.bundles = x509bundle.NewSet()
	s.mtx.Unlock()

	s.triggerUpdated()
}

func wrapX509SourceErr(err error) error {
	return fmt.Errorf("x509source: %w", err)
}
