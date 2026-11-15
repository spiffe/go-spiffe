package brokerapi

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/protobuf/proto"
)

// BundleSource is a source of X.509 and JWT bundles maintained via the Broker
// API for a specific workload reference. It implements both x509bundle.Source
// and jwtbundle.Source.
//
// Experimental: subject to change.
type BundleSource struct {
	sourceBase

	client    *Client
	reference *brokerpb.WorkloadReference

	mtx         sync.RWMutex
	x509Bundles *x509bundle.Set
	jwtBundles  *jwtbundle.Set

	x509BundlesSet     chan struct{}
	x509BundlesSetOnce sync.Once
	jwtBundlesSet      chan struct{}
	jwtBundlesSetOnce  sync.Once
}

// NewBundleSource creates a new BundleSource for the given workload reference.
// It blocks until the initial updates have been received from the Broker API.
// The source should be closed when no longer in use.
//
// The source does not own the client. The client should be closed separately
// once all sources created from it are closed.
//
// Experimental: subject to change.
func NewBundleSource(ctx context.Context, client *Client, workloadReference proto.Message) (_ *BundleSource, err error) {
	if err := validateClient(client); err != nil {
		return nil, err
	}

	reference, err := newWorkloadReference(workloadReference)
	if err != nil {
		return nil, err
	}

	s := &BundleSource{
		sourceBase:     newSourceBase(),
		client:         client,
		reference:      reference,
		x509Bundles:    x509bundle.NewSet(),
		jwtBundles:     jwtbundle.NewSet(),
		x509BundlesSet: make(chan struct{}),
		jwtBundlesSet:  make(chan struct{}),
	}

	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
		}
	}()

	errCh := make(chan error, 2)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		errCh <- s.watchX509Bundles(s.ctx)
	}()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		errCh <- s.watchJWTBundles(s.ctx)
	}()

	waitFor := func(has <-chan struct{}) error {
		select {
		case <-has:
			return nil
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if err := waitFor(s.x509BundlesSet); err != nil {
		return nil, err
	}
	if err := waitFor(s.jwtBundlesSet); err != nil {
		return nil, err
	}

	s.drainUpdated()
	return s, nil
}

// NewBundleSource creates a new BundleSource for the given workload reference.
// It is a convenience method that calls the package-level NewBundleSource.
//
// Experimental: subject to change.
func (c *Client) NewBundleSource(ctx context.Context, workloadReference proto.Message) (*BundleSource, error) {
	return NewBundleSource(ctx, c, workloadReference)
}

// Close closes the source, dropping the streams to the Broker API. Other
// source methods will return an error after Close has been called.
//
// Experimental: subject to change.
func (s *BundleSource) Close() error {
	return s.close()
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface.
//
// Experimental: subject to change.
func (s *BundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, wrapBundleSourceErr(err)
	}

	s.mtx.RLock()
	bundles := s.x509Bundles
	s.mtx.RUnlock()

	if bundles == nil {
		return nil, wrapBundleSourceErr(errors.New("missing X.509 bundles"))
	}
	return bundles.GetX509BundleForTrustDomain(trustDomain)
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust
// domain. It implements the jwtbundle.Source interface.
//
// Experimental: subject to change.
func (s *BundleSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, wrapBundleSourceErr(err)
	}

	s.mtx.RLock()
	bundles := s.jwtBundles
	s.mtx.RUnlock()

	if bundles == nil {
		return nil, wrapBundleSourceErr(errors.New("missing JWT bundles"))
	}
	return bundles.GetJWTBundleForTrustDomain(trustDomain)
}

// WaitUntilUpdated waits until the source is updated or the context is done,
// in which case ctx.Err() is returned.
//
// Experimental: subject to change.
func (s *BundleSource) WaitUntilUpdated(ctx context.Context) error {
	return s.waitUntilUpdated(ctx)
}

// Updated returns a channel that is sent on whenever the source is updated.
//
// Experimental: subject to change.
func (s *BundleSource) Updated() <-chan struct{} {
	return s.updated()
}

func (s *BundleSource) watchX509Bundles(ctx context.Context) error {
	return watch(ctx, s.client.config.log, s.client.config.backoffStrategy, "X.509 bundles", s.openX509Bundles, s.updateX509Bundles, s.clearX509Bundles)
}

func (s *BundleSource) openX509Bundles(ctx context.Context) (recvFunc[*brokerpb.SubscribeToX509BundlesResponse], error) {
	stream, err := s.client.apiClient.SubscribeToX509Bundles(ctx, &brokerpb.SubscribeToX509BundlesRequest{
		Reference: s.reference,
	})
	if err != nil {
		return nil, err
	}
	return stream.Recv, nil
}

func (s *BundleSource) updateX509Bundles(response *brokerpb.SubscribeToX509BundlesResponse) error {
	bundles, err := parseX509Bundles(response)
	if err != nil {
		return err
	}

	s.mtx.Lock()
	s.x509Bundles = bundles
	s.mtx.Unlock()

	s.triggerUpdated()
	s.x509BundlesSetOnce.Do(func() {
		close(s.x509BundlesSet)
	})
	return nil
}

func (s *BundleSource) clearX509Bundles() {
	s.mtx.Lock()
	s.x509Bundles = x509bundle.NewSet()
	s.mtx.Unlock()

	s.triggerUpdated()
}

func (s *BundleSource) watchJWTBundles(ctx context.Context) error {
	return watch(ctx, s.client.config.log, s.client.config.backoffStrategy, "JWT bundles", s.openJWTBundles, s.updateJWTBundles, s.clearJWTBundles)
}

func (s *BundleSource) openJWTBundles(ctx context.Context) (recvFunc[*brokerpb.SubscribeToJWTBundlesResponse], error) {
	stream, err := s.client.apiClient.SubscribeToJWTBundles(ctx, &brokerpb.SubscribeToJWTBundlesRequest{
		Reference: s.reference,
	})
	if err != nil {
		return nil, err
	}
	return stream.Recv, nil
}

func (s *BundleSource) updateJWTBundles(response *brokerpb.SubscribeToJWTBundlesResponse) error {
	bundles, err := parseJWTBundles(response)
	if err != nil {
		return err
	}

	s.mtx.Lock()
	s.jwtBundles = bundles
	s.mtx.Unlock()

	s.triggerUpdated()
	s.jwtBundlesSetOnce.Do(func() {
		close(s.jwtBundlesSet)
	})
	return nil
}

func (s *BundleSource) clearJWTBundles() {
	s.mtx.Lock()
	s.jwtBundles = jwtbundle.NewSet()
	s.mtx.Unlock()

	s.triggerUpdated()
}

func wrapBundleSourceErr(err error) error {
	return fmt.Errorf("bundlesource: %w", err)
}
