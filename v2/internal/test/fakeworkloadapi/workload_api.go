package fakeworkloadapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var noIdentityError = status.Error(codes.PermissionDenied, "no identity issued")

type WorkloadAPI struct {
	tb              testing.TB
	wg              sync.WaitGroup
	addr            string
	server          *grpc.Server
	mu              sync.Mutex
	x509Resp        *workload.X509SVIDResponse
	x509Chans       map[chan *workload.X509SVIDResponse]struct{}
	jwtResp         *workload.JWTSVIDResponse
	jwtBundlesResp  *workload.JWTBundlesResponse
	jwtBundlesChans map[chan *workload.JWTBundlesResponse]struct{}
}

func NewWorkloadAPI(tb testing.TB) *WorkloadAPI {
	w := &WorkloadAPI{
		x509Chans:       make(map[chan *workload.X509SVIDResponse]struct{}),
		jwtBundlesChans: make(map[chan *workload.JWTBundlesResponse]struct{}),
	}

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(tb, err)

	server := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(server, &workloadAPIWrapper{w: w})

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		_ = server.Serve(listener)
	}()

	w.addr = fmt.Sprintf("%s://%s", listener.Addr().Network(), listener.Addr().String())
	tb.Logf("WorkloadAPI address: %s", w.addr)
	w.server = server
	return w
}

func (w *WorkloadAPI) Stop() {
	w.server.Stop()
	w.wg.Wait()
}

func (w *WorkloadAPI) Addr() string {
	return w.addr
}

func (w *WorkloadAPI) SetX509SVIDResponse(r *X509SVIDResponse) {
	var resp *workload.X509SVIDResponse
	if r != nil {
		resp = r.ToProto(w.tb)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.x509Resp = resp

	for ch := range w.x509Chans {
		select {
		case ch <- resp:
		default:
			<-ch
			ch <- resp
		}
	}
}

func (w *WorkloadAPI) SetJWTSVIDResponse(r *workload.JWTSVIDResponse) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r != nil {
		w.jwtResp = r
	}
}

func (w *WorkloadAPI) SetJWTBundle(trustDomain string, jwtAuthorities map[string]crypto.PublicKey) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		w.tb.Error(err)
		return
	}

	jwtBundle := jwtbundle.FromJWTAuthorities(td, jwtAuthorities)
	b, err := jwtBundle.Marshal()
	if err != nil {
		w.tb.Error(err)
		return
	}

	resp := &workload.JWTBundlesResponse{
		Bundles: map[string][]byte{jwtBundle.TrustDomain().String(): b},
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.jwtBundlesResp = resp

	for ch := range w.jwtBundlesChans {
		select {
		case ch <- w.jwtBundlesResp:
		default:
			<-ch
			ch <- w.jwtBundlesResp
		}
	}
}

type workloadAPIWrapper struct {
	w *WorkloadAPI
}

func (w *workloadAPIWrapper) FetchX509SVID(req *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	return w.w.fetchX509SVID(req, stream)
}

func (w *workloadAPIWrapper) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	return w.w.fetchJWTSVID(ctx, req)
}

func (w *workloadAPIWrapper) FetchJWTBundles(req *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	return w.w.fetchJWTBundles(req, stream)
}

func (w *workloadAPIWrapper) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	return w.w.validateJWTSVID(ctx, req)
}

type X509SVID struct {
	CertChain []*x509.Certificate
	Key       crypto.Signer
}

type X509SVIDResponse struct {
	SVIDs            []X509SVID
	Bundle           []*x509.Certificate
	FederatedBundles map[string][]*x509.Certificate
}

func (r *X509SVIDResponse) ToProto(tb testing.TB) *workload.X509SVIDResponse {
	bundle := derBlobFromCerts(r.Bundle)

	pb := &workload.X509SVIDResponse{
		FederatedBundles: make(map[string][]byte),
	}
	for _, svid := range r.SVIDs {
		// The workload API should always respond with at one certificate and a
		// private key but making this optional here is needed for some test
		// flexibility.
		var spiffeID string
		if len(svid.CertChain) > 0 && len(svid.CertChain[0].URIs) > 0 {
			spiffeID = svid.CertChain[0].URIs[0].String()
		}
		var keyDER []byte
		if svid.Key != nil {
			var err error
			keyDER, err = x509.MarshalPKCS8PrivateKey(svid.Key)
			require.NoError(tb, err)
		}
		pb.Svids = append(pb.Svids, &workload.X509SVID{
			SpiffeId:    spiffeID,
			X509Svid:    derBlobFromCerts(svid.CertChain),
			X509SvidKey: keyDER,
			Bundle:      bundle,
		})
	}
	for k, v := range r.FederatedBundles {
		pb.FederatedBundles[k] = derBlobFromCerts(v)
	}

	return pb
}

func (w *WorkloadAPI) fetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := checkHeader(stream.Context()); err != nil {
		return err
	}
	ch := make(chan *workload.X509SVIDResponse, 1)
	w.mu.Lock()
	w.x509Chans[ch] = struct{}{}
	resp := w.x509Resp
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		delete(w.x509Chans, ch)
		w.mu.Unlock()
	}()

	sendResp := func(resp *workload.X509SVIDResponse) error {
		if resp == nil {
			return noIdentityError
		}
		return stream.Send(resp)
	}

	if err := sendResp(resp); err != nil {
		return err
	}
	for {
		select {
		case resp := <-ch:
			if err := sendResp(resp); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (w *WorkloadAPI) fetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	if err := checkHeader(ctx); err != nil {
		return nil, err
	}
	if len(req.Audience) == 0 {
		return nil, errors.New("no audience")
	}
	if w.jwtResp == nil {
		return nil, noIdentityError
	}

	return w.jwtResp, nil
}

func (w *WorkloadAPI) fetchJWTBundles(_ *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	if err := checkHeader(stream.Context()); err != nil {
		return err
	}
	ch := make(chan *workload.JWTBundlesResponse, 1)
	w.mu.Lock()
	w.jwtBundlesChans[ch] = struct{}{}
	resp := w.jwtBundlesResp
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		delete(w.jwtBundlesChans, ch)
		w.mu.Unlock()
	}()

	sendResp := func(resp *workload.JWTBundlesResponse) error {
		if resp == nil {
			return noIdentityError
		}
		return stream.Send(resp)
	}

	if err := sendResp(resp); err != nil {
		return err
	}
	for {
		select {
		case resp := <-ch:
			if err := sendResp(resp); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (w *WorkloadAPI) validateJWTSVID(_ context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	if req.Audience == "" {
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}

	if req.Svid == "" {
		return nil, status.Error(codes.InvalidArgument, "svid must be specified")
	}

	jwtSvid, err := jwtsvid.ParseInsecure(req.Svid, []string{req.Audience})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	claims, err := structFromValues(jwtSvid.Claims)
	require.NoError(w.tb, err)

	return &workload.ValidateJWTSVIDResponse{
		SpiffeId: jwtSvid.ID.String(),
		Claims:   claims,
	}, nil
}

func derBlobFromCerts(certs []*x509.Certificate) []byte {
	var der []byte
	for _, cert := range certs {
		der = append(der, cert.Raw...)
	}
	return der
}

func checkHeader(ctx context.Context) error {
	return checkMetadata(ctx, "workload.spiffe.io", "true")
}

func checkMetadata(ctx context.Context, key, value string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errors.New("request does not contain metadata")
	}
	values := md.Get(key)
	if len(value) == 0 {
		return fmt.Errorf("request metadata does not contain %q value", key)
	}
	if values[0] != value {
		return fmt.Errorf("request metadata %q value is %q; expected %q", key, values[0], value)
	}
	return nil
}

func structFromValues(values map[string]interface{}) (*structpb.Struct, error) {
	valuesJSON, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}

	s := new(structpb.Struct)
	if err := jsonpb.Unmarshal(bytes.NewReader(valuesJSON), s); err != nil {
		return nil, err
	}

	return s, nil
}
