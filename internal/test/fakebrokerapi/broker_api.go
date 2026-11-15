package fakebrokerapi

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var noIdentityError = status.Error(codes.PermissionDenied, "no identity issued")

type BrokerAPI struct {
	tb     testing.TB
	wg     sync.WaitGroup
	addr   string
	server *grpc.Server

	mu                sync.Mutex
	x509SVIDResp      *brokerpb.SubscribeToX509SVIDResponse
	x509SVIDChans     map[chan *brokerpb.SubscribeToX509SVIDResponse]struct{}
	x509BundlesResp   *brokerpb.SubscribeToX509BundlesResponse
	x509BundlesChans  map[chan *brokerpb.SubscribeToX509BundlesResponse]struct{}
	jwtBundlesResp    *brokerpb.SubscribeToJWTBundlesResponse
	jwtBundlesChans   map[chan *brokerpb.SubscribeToJWTBundlesResponse]struct{}
	jwtSVIDResp       *brokerpb.FetchJWTSVIDResponse
	lastReference     *brokerpb.WorkloadReference
	lastReferenceCh   chan struct{}
	lastReferenceOnce sync.Once
}

func New(tb testing.TB) *BrokerAPI {
	b := &BrokerAPI{
		tb:               tb,
		x509SVIDChans:    make(map[chan *brokerpb.SubscribeToX509SVIDResponse]struct{}),
		x509BundlesChans: make(map[chan *brokerpb.SubscribeToX509BundlesResponse]struct{}),
		jwtBundlesChans:  make(map[chan *brokerpb.SubscribeToJWTBundlesResponse]struct{}),
		lastReferenceCh:  make(chan struct{}),
	}

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(tb, err)

	server := grpc.NewServer()
	brokerpb.RegisterAPIServer(server, &apiServer{b: b})

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		_ = server.Serve(listener)
	}()

	b.addr = "tcp://" + listener.Addr().String()
	b.server = server
	tb.Logf("BrokerAPI address: %s", b.addr)
	return b
}

func (b *BrokerAPI) Addr() string {
	return b.addr
}

func (b *BrokerAPI) Stop() {
	b.server.Stop()
	b.wg.Wait()
}

func (b *BrokerAPI) SetX509SVIDResponse(resp *brokerpb.SubscribeToX509SVIDResponse) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.x509SVIDResp = resp
	for ch := range b.x509SVIDChans {
		sendLatest(ch, resp)
	}
}

func (b *BrokerAPI) SetX509BundlesResponse(resp *brokerpb.SubscribeToX509BundlesResponse) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.x509BundlesResp = resp
	for ch := range b.x509BundlesChans {
		sendLatest(ch, resp)
	}
}

func (b *BrokerAPI) SetJWTBundlesResponse(resp *brokerpb.SubscribeToJWTBundlesResponse) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.jwtBundlesResp = resp
	for ch := range b.jwtBundlesChans {
		sendLatest(ch, resp)
	}
}

func (b *BrokerAPI) SetJWTSVIDResponse(resp *brokerpb.FetchJWTSVIDResponse) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.jwtSVIDResp = resp
}

func (b *BrokerAPI) LastReference() *brokerpb.WorkloadReference {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastReference
}

func (b *BrokerAPI) WaitForRequest(tb testing.TB) {
	tb.Helper()
	select {
	case <-b.lastReferenceCh:
	case <-time.After(time.Minute):
		require.FailNow(tb, "timed out waiting for a Broker API request")
	}
}

func sendLatest[T any](ch chan T, value T) {
	select {
	case ch <- value:
	default:
		<-ch
		ch <- value
	}
}

func (b *BrokerAPI) recordReference(reference *brokerpb.WorkloadReference) error {
	if reference == nil || reference.Reference == nil {
		return status.Error(codes.InvalidArgument, "workload reference is required")
	}

	b.mu.Lock()
	b.lastReference = reference
	b.mu.Unlock()

	b.lastReferenceOnce.Do(func() {
		close(b.lastReferenceCh)
	})
	return nil
}

type apiServer struct {
	brokerpb.UnimplementedAPIServer
	b *BrokerAPI
}

func (s *apiServer) SubscribeToX509SVID(req *brokerpb.SubscribeToX509SVIDRequest, stream grpc.ServerStreamingServer[brokerpb.SubscribeToX509SVIDResponse]) error {
	if err := s.b.recordReference(req.Reference); err != nil {
		return err
	}

	ch := make(chan *brokerpb.SubscribeToX509SVIDResponse, 1)
	s.b.mu.Lock()
	s.b.x509SVIDChans[ch] = struct{}{}
	resp := s.b.x509SVIDResp
	s.b.mu.Unlock()

	defer func() {
		s.b.mu.Lock()
		delete(s.b.x509SVIDChans, ch)
		s.b.mu.Unlock()
	}()

	send := func(resp *brokerpb.SubscribeToX509SVIDResponse) error {
		if resp == nil {
			return noIdentityError
		}
		return stream.Send(resp)
	}

	if err := send(resp); err != nil {
		return err
	}

	for {
		select {
		case resp := <-ch:
			if err := send(resp); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *apiServer) SubscribeToX509Bundles(req *brokerpb.SubscribeToX509BundlesRequest, stream grpc.ServerStreamingServer[brokerpb.SubscribeToX509BundlesResponse]) error {
	if err := s.b.recordReference(req.Reference); err != nil {
		return err
	}

	ch := make(chan *brokerpb.SubscribeToX509BundlesResponse, 1)
	s.b.mu.Lock()
	s.b.x509BundlesChans[ch] = struct{}{}
	resp := s.b.x509BundlesResp
	s.b.mu.Unlock()

	defer func() {
		s.b.mu.Lock()
		delete(s.b.x509BundlesChans, ch)
		s.b.mu.Unlock()
	}()

	send := func(resp *brokerpb.SubscribeToX509BundlesResponse) error {
		if resp == nil {
			return noIdentityError
		}
		return stream.Send(resp)
	}

	if err := send(resp); err != nil {
		return err
	}

	for {
		select {
		case resp := <-ch:
			if err := send(resp); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *apiServer) FetchJWTSVID(_ context.Context, req *brokerpb.FetchJWTSVIDRequest) (*brokerpb.FetchJWTSVIDResponse, error) {
	if err := s.b.recordReference(req.Reference); err != nil {
		return nil, err
	}
	if len(req.Audience) == 0 {
		return nil, status.Error(codes.InvalidArgument, "audience is required")
	}

	s.b.mu.Lock()
	resp := s.b.jwtSVIDResp
	s.b.mu.Unlock()

	if resp == nil {
		return nil, noIdentityError
	}

	if req.SpiffeId == "" {
		return resp, nil
	}

	filtered := &brokerpb.FetchJWTSVIDResponse{}
	for _, svid := range resp.Svids {
		if svid.SpiffeId == req.SpiffeId {
			filtered.Svids = append(filtered.Svids, svid)
		}
	}
	return filtered, nil
}

func (s *apiServer) SubscribeToJWTBundles(req *brokerpb.SubscribeToJWTBundlesRequest, stream grpc.ServerStreamingServer[brokerpb.SubscribeToJWTBundlesResponse]) error {
	if err := s.b.recordReference(req.Reference); err != nil {
		return err
	}

	ch := make(chan *brokerpb.SubscribeToJWTBundlesResponse, 1)
	s.b.mu.Lock()
	s.b.jwtBundlesChans[ch] = struct{}{}
	resp := s.b.jwtBundlesResp
	s.b.mu.Unlock()

	defer func() {
		s.b.mu.Lock()
		delete(s.b.jwtBundlesChans, ch)
		s.b.mu.Unlock()
	}()

	send := func(resp *brokerpb.SubscribeToJWTBundlesResponse) error {
		if resp == nil {
			return noIdentityError
		}
		return stream.Send(resp)
	}

	if err := send(resp); err != nil {
		return err
	}

	for {
		select {
		case resp := <-ch:
			if err := send(resp); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}
