package fakebrokerapi

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	brokerMetadataKey = "broker.spiffe.io"
	brokerTrustDomain = "domain.test"
	brokerPath        = "/broker"
	clientPath        = "/client"
)

var noIdentityError = status.Error(codes.PermissionDenied, "no identity issued")

type BrokerAPI struct {
	tb     testing.TB
	wg     sync.WaitGroup
	addr   string
	server *grpc.Server

	ca         *test.CA
	serverID   spiffeid.ID
	clientSVID *x509svid.SVID

	mu                sync.Mutex
	x509SVIDResp      *brokerpb.SubscribeToX509SVIDResponse
	x509SVIDErr       error
	x509SVIDChans     map[chan *brokerpb.SubscribeToX509SVIDResponse]struct{}
	x509BundlesResp   *brokerpb.SubscribeToX509BundlesResponse
	x509BundlesErr    error
	x509BundlesChans  map[chan *brokerpb.SubscribeToX509BundlesResponse]struct{}
	jwtBundlesResp    *brokerpb.SubscribeToJWTBundlesResponse
	jwtBundlesErr     error
	jwtBundlesChans   map[chan *brokerpb.SubscribeToJWTBundlesResponse]struct{}
	jwtSVIDResp       *brokerpb.FetchJWTSVIDResponse
	jwtSVIDErr        error
	lastReference     *brokerpb.WorkloadReference
	lastReferenceCh   chan struct{}
	lastReferenceOnce sync.Once

	requestsByLocalAddr map[string]int
}

func New(tb testing.TB) *BrokerAPI {
	td := spiffeid.RequireTrustDomainFromString(brokerTrustDomain)
	ca := test.NewCA(tb, td)
	serverSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, brokerPath))
	clientSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, clientPath))

	b := &BrokerAPI{
		tb:                  tb,
		ca:                  ca,
		serverID:            serverSVID.ID,
		clientSVID:          clientSVID,
		x509SVIDChans:       make(map[chan *brokerpb.SubscribeToX509SVIDResponse]struct{}),
		x509BundlesChans:    make(map[chan *brokerpb.SubscribeToX509BundlesResponse]struct{}),
		jwtBundlesChans:     make(map[chan *brokerpb.SubscribeToJWTBundlesResponse]struct{}),
		lastReferenceCh:     make(chan struct{}),
		requestsByLocalAddr: make(map[string]int),
	}

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(tb, err)

	server := grpc.NewServer(grpc.Creds(grpccredentials.MTLSServerCredentials(
		serverSVID,
		ca.X509Bundle(),
		tlsconfig.AuthorizeAny(),
	)))
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

// AddListener starts serving the Broker API on another TCP listener and
// returns the listener address.
func (b *BrokerAPI) AddListener(tb testing.TB) string {
	tb.Helper()

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(tb, err)

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		_ = b.server.Serve(listener)
	}()

	return listener.Addr().String()
}

// Bundle returns the X.509 bundle trusted by the Broker API server.
func (b *BrokerAPI) Bundle() *x509bundle.Bundle {
	return b.ca.X509Bundle()
}

// MTLSClientSVID returns an X509-SVID authorized by the Broker API server.
func (b *BrokerAPI) MTLSClientSVID() *x509svid.SVID {
	return b.clientSVID
}

// ServerID returns the SPIFFE ID of the Broker API server X509-SVID.
func (b *BrokerAPI) ServerID() spiffeid.ID {
	return b.serverID
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

func (b *BrokerAPI) SetX509SVIDError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.x509SVIDErr = err
}

func (b *BrokerAPI) SetX509BundlesResponse(resp *brokerpb.SubscribeToX509BundlesResponse) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.x509BundlesResp = resp
	for ch := range b.x509BundlesChans {
		sendLatest(ch, resp)
	}
}

func (b *BrokerAPI) SetX509BundlesError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.x509BundlesErr = err
}

func (b *BrokerAPI) SetJWTBundlesResponse(resp *brokerpb.SubscribeToJWTBundlesResponse) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.jwtBundlesResp = resp
	for ch := range b.jwtBundlesChans {
		sendLatest(ch, resp)
	}
}

func (b *BrokerAPI) SetJWTBundlesError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.jwtBundlesErr = err
}

func (b *BrokerAPI) SetJWTSVIDResponse(resp *brokerpb.FetchJWTSVIDResponse) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.jwtSVIDResp = resp
}

func (b *BrokerAPI) SetJWTSVIDError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.jwtSVIDErr = err
}

// RequestCountsByLocalAddr returns the number of requests received on each
// local listener address.
func (b *BrokerAPI) RequestCountsByLocalAddr() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()

	counts := make(map[string]int, len(b.requestsByLocalAddr))
	for addr, count := range b.requestsByLocalAddr {
		counts[addr] = count
	}
	return counts
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
	case <-ch:
	default:
	}
	ch <- value
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

func (b *BrokerAPI) recordRequest(ctx context.Context) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return
	}

	b.mu.Lock()
	b.requestsByLocalAddr[p.LocalAddr.String()]++
	b.mu.Unlock()
}

func checkHeader(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.InvalidArgument, "request does not contain metadata")
	}
	values := md.Get(brokerMetadataKey)
	if len(values) == 0 {
		return status.Error(codes.InvalidArgument, "request metadata does not contain broker.spiffe.io value")
	}
	if values[0] != "true" {
		return status.Error(codes.InvalidArgument, "request metadata broker.spiffe.io value is not true")
	}
	return nil
}

type apiServer struct {
	brokerpb.UnimplementedAPIServer
	b *BrokerAPI
}

func (s *apiServer) SubscribeToX509SVID(req *brokerpb.SubscribeToX509SVIDRequest, stream grpc.ServerStreamingServer[brokerpb.SubscribeToX509SVIDResponse]) error {
	if err := checkHeader(stream.Context()); err != nil {
		return err
	}
	s.b.recordRequest(stream.Context())
	if err := s.b.recordReference(req.Reference); err != nil {
		return err
	}

	ch := make(chan *brokerpb.SubscribeToX509SVIDResponse, 1)
	s.b.mu.Lock()
	s.b.x509SVIDChans[ch] = struct{}{}
	resp := s.b.x509SVIDResp
	respErr := s.b.x509SVIDErr
	s.b.mu.Unlock()

	defer func() {
		s.b.mu.Lock()
		delete(s.b.x509SVIDChans, ch)
		s.b.mu.Unlock()
	}()

	if respErr != nil {
		return respErr
	}

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
	if err := checkHeader(stream.Context()); err != nil {
		return err
	}
	s.b.recordRequest(stream.Context())
	if err := s.b.recordReference(req.Reference); err != nil {
		return err
	}

	ch := make(chan *brokerpb.SubscribeToX509BundlesResponse, 1)
	s.b.mu.Lock()
	s.b.x509BundlesChans[ch] = struct{}{}
	resp := s.b.x509BundlesResp
	respErr := s.b.x509BundlesErr
	s.b.mu.Unlock()

	defer func() {
		s.b.mu.Lock()
		delete(s.b.x509BundlesChans, ch)
		s.b.mu.Unlock()
	}()

	if respErr != nil {
		return respErr
	}

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

func (s *apiServer) FetchJWTSVID(ctx context.Context, req *brokerpb.FetchJWTSVIDRequest) (*brokerpb.FetchJWTSVIDResponse, error) {
	if err := checkHeader(ctx); err != nil {
		return nil, err
	}
	s.b.recordRequest(ctx)
	if err := s.b.recordReference(req.Reference); err != nil {
		return nil, err
	}
	if len(req.Audience) == 0 {
		return nil, status.Error(codes.InvalidArgument, "audience is required")
	}

	s.b.mu.Lock()
	resp := s.b.jwtSVIDResp
	respErr := s.b.jwtSVIDErr
	s.b.mu.Unlock()

	if respErr != nil {
		return nil, respErr
	}
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
	if err := checkHeader(stream.Context()); err != nil {
		return err
	}
	s.b.recordRequest(stream.Context())
	if err := s.b.recordReference(req.Reference); err != nil {
		return err
	}

	ch := make(chan *brokerpb.SubscribeToJWTBundlesResponse, 1)
	s.b.mu.Lock()
	s.b.jwtBundlesChans[ch] = struct{}{}
	resp := s.b.jwtBundlesResp
	respErr := s.b.jwtBundlesErr
	s.b.mu.Unlock()

	defer func() {
		s.b.mu.Lock()
		delete(s.b.jwtBundlesChans, ch)
		s.b.mu.Unlock()
	}()

	if respErr != nil {
		return respErr
	}

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
