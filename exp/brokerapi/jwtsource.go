package brokerapi

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"google.golang.org/protobuf/proto"
)

// JWTSource is a source of JWT-SVIDs and JWT bundles maintained via the Broker
// API for a specific workload reference. It implements both jwtsvid.Source
// and jwtbundle.Source.
//
// Experimental: subject to change.
type JWTSource struct {
	sourceBase

	client    *Client
	reference *brokerpb.WorkloadReference
	picker    func([]*jwtsvid.SVID) *jwtsvid.SVID

	mtx     sync.RWMutex
	bundles *jwtbundle.Set

	jwtBundlesSet     chan struct{}
	jwtBundlesSetOnce sync.Once
}

// NewJWTSource creates a new JWTSource for the given workload reference. It
// blocks until the initial update has been received from the Broker API. The
// source should be closed when no longer in use.
//
// The source does not own the client. The client should be closed separately
// once all sources created from it are closed.
//
// Experimental: subject to change.
func NewJWTSource(ctx context.Context, client *Client, workloadReference proto.Message, options ...JWTSourceOption) (_ *JWTSource, err error) {
	if err := validateClient(client); err != nil {
		return nil, err
	}

	config := &jwtSourceConfig{}
	for _, option := range options {
		option.configureJWTSource(config)
	}

	reference, err := newWorkloadReference(workloadReference)
	if err != nil {
		return nil, err
	}

	s := &JWTSource{
		sourceBase:    newSourceBase(),
		client:        client,
		reference:     reference,
		picker:        config.picker,
		bundles:       jwtbundle.NewSet(),
		jwtBundlesSet: make(chan struct{}),
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
	case <-s.jwtBundlesSet:
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	s.drainUpdated()
	return s, nil
}

// NewJWTSource creates a new JWTSource for the given workload reference. It is
// a convenience method that calls the package-level NewJWTSource.
//
// Experimental: subject to change.
func (c *Client) NewJWTSource(ctx context.Context, workloadReference proto.Message, options ...JWTSourceOption) (*JWTSource, error) {
	return NewJWTSource(ctx, c, workloadReference, options...)
}

// Close closes the source, dropping the streams to the Broker API. Other
// source methods will return an error after Close has been called.
//
// Experimental: subject to change.
func (s *JWTSource) Close() error {
	return s.close()
}

// FetchJWTSVID fetches a JWT-SVID from the source with the given parameters.
// It implements the jwtsvid.Source interface.
//
// Experimental: subject to change.
func (s *JWTSource) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	if err := s.checkClosed(); err != nil {
		return nil, wrapJWTSourceErr(err)
	}

	svids, err := s.fetchJWTSVIDs(ctx, params)
	if err != nil {
		return nil, err
	}

	if s.picker == nil {
		return svids[0], nil
	}

	svid := s.picker(svids)
	if svid == nil {
		return nil, wrapJWTSourceErr(errors.New("JWT-SVID picker returned nil"))
	}
	return svid, nil
}

// FetchJWTSVIDs fetches all JWT-SVIDs from the source with the given
// parameters.
//
// Experimental: subject to change.
func (s *JWTSource) FetchJWTSVIDs(ctx context.Context, params jwtsvid.Params) ([]*jwtsvid.SVID, error) {
	if err := s.checkClosed(); err != nil {
		return nil, wrapJWTSourceErr(err)
	}
	return s.fetchJWTSVIDs(ctx, params)
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust
// domain. It implements the jwtbundle.Source interface.
//
// Experimental: subject to change.
func (s *JWTSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, wrapJWTSourceErr(err)
	}

	s.mtx.RLock()
	bundles := s.bundles
	s.mtx.RUnlock()

	if bundles == nil {
		return nil, wrapJWTSourceErr(errors.New("missing JWT bundles"))
	}
	return bundles.GetJWTBundleForTrustDomain(trustDomain)
}

// WaitUntilUpdated waits until the source is updated or the context is done,
// in which case ctx.Err() is returned.
//
// Experimental: subject to change.
func (s *JWTSource) WaitUntilUpdated(ctx context.Context) error {
	return s.waitUntilUpdated(ctx)
}

// Updated returns a channel that is sent on whenever the source is updated.
//
// Experimental: subject to change.
func (s *JWTSource) Updated() <-chan struct{} {
	return s.updated()
}

func (s *JWTSource) watch(ctx context.Context) error {
	return watch(ctx, s.client.config.log, s.client.config.backoffStrategy, "JWT bundles", s.open, s.update, s.clear)
}

func (s *JWTSource) open(ctx context.Context) (recvFunc[*brokerpb.SubscribeToJWTBundlesResponse], error) {
	stream, err := s.client.apiClient.SubscribeToJWTBundles(ctx, &brokerpb.SubscribeToJWTBundlesRequest{
		Reference: s.reference,
	})
	if err != nil {
		return nil, err
	}
	return stream.Recv, nil
}

func (s *JWTSource) update(response *brokerpb.SubscribeToJWTBundlesResponse) error {
	bundles, err := parseJWTBundles(response)
	if err != nil {
		return err
	}

	s.mtx.Lock()
	s.bundles = bundles
	s.mtx.Unlock()

	s.triggerUpdated()
	s.jwtBundlesSetOnce.Do(func() {
		close(s.jwtBundlesSet)
	})
	return nil
}

func (s *JWTSource) clear() {
	s.mtx.Lock()
	s.bundles = jwtbundle.NewSet()
	s.mtx.Unlock()

	s.triggerUpdated()
}

func (s *JWTSource) fetchJWTSVIDs(ctx context.Context, params jwtsvid.Params) ([]*jwtsvid.SVID, error) {
	audience, err := jwtAudience(params)
	if err != nil {
		return nil, wrapJWTSourceErr(err)
	}

	response, err := s.client.apiClient.FetchJWTSVID(ctx, &brokerpb.FetchJWTSVIDRequest{
		Reference: s.reference,
		Audience:  audience,
		SpiffeId:  params.Subject.String(),
	})
	if err != nil {
		return nil, err
	}

	return parseJWTSVIDs(response, audience)
}

func wrapJWTSourceErr(err error) error {
	return fmt.Errorf("jwtsource: %w", err)
}
