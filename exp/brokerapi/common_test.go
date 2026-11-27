package brokerapi_test

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/exp/brokerapi"
	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebrokerapi"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/internal/x509util"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type instantBackoffStrategy struct{}

func (instantBackoffStrategy) NewBackoff() workloadapi.Backoff {
	return instantBackoff{}
}

type instantBackoff struct{}

func (instantBackoff) Next() time.Duration { return time.Millisecond }
func (instantBackoff) Reset()              {}

func newTestClient(tb testing.TB, api *fakebrokerapi.BrokerAPI) *brokerapi.Client {
	tb.Helper()

	workloadAPI := newTestWorkloadAPI(tb, api)

	client, err := brokerapi.New(context.Background(),
		tlsconfig.AuthorizeID(api.ServerID()),
		brokerapi.WithAddr(api.Addr()),
		brokerapi.WithWorkloadAPISourceOptions(
			workloadapi.WithClientOptions(workloadapi.WithAddr(workloadAPI.Addr())),
		),
		brokerapi.WithBackoffStrategy(instantBackoffStrategy{}),
	)
	require.NoError(tb, err)
	tb.Cleanup(func() {
		require.NoError(tb, client.Close())
	})
	return client
}

func newTestWorkloadAPI(tb testing.TB, api *fakebrokerapi.BrokerAPI) *fakeworkloadapi.WorkloadAPI {
	tb.Helper()

	workloadAPI := fakeworkloadapi.New(tb)
	tb.Cleanup(workloadAPI.Stop)
	workloadAPI.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{api.MTLSClientSVID()},
		Bundle: api.Bundle(),
	})
	return workloadAPI
}

func workloadReference() *brokerpb.WorkloadPIDReference {
	return &brokerpb.WorkloadPIDReference{Pid: 1234}
}

func requireWorkloadReference(tb testing.TB, api *fakebrokerapi.BrokerAPI, expected *brokerpb.WorkloadPIDReference) {
	tb.Helper()

	reference := api.LastReference()
	require.NotNil(tb, reference)
	require.NotNil(tb, reference.Reference)
	require.Equal(tb, "type.googleapis.com/spiffe.broker.WorkloadPIDReference", reference.Reference.TypeUrl)

	actual := new(brokerpb.WorkloadPIDReference)
	require.NoError(tb, reference.Reference.UnmarshalTo(actual))
	require.True(tb, proto.Equal(expected, actual))
}

func makeX509SVIDResponse(tb testing.TB, bundle *x509bundle.Bundle, svids []*x509svid.SVID, federatedBundles ...*x509bundle.Bundle) *brokerpb.SubscribeToX509SVIDResponse {
	tb.Helper()

	response := &brokerpb.SubscribeToX509SVIDResponse{
		FederatedBundles: make(map[string][]byte),
	}

	var bundleBytes []byte
	if bundle != nil {
		bundleBytes = x509util.ConcatRawCertsFromCerts(bundle.X509Authorities())
	}

	for _, svid := range svids {
		keyBytes, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
		require.NoError(tb, err)

		response.Svids = append(response.Svids, &brokerpb.X509SVID{
			SpiffeId:    svid.ID.String(),
			X509Svid:    x509util.ConcatRawCertsFromCerts(svid.Certificates),
			X509SvidKey: keyBytes,
			Bundle:      bundleBytes,
			Hint:        svid.Hint,
		})
	}

	for _, federatedBundle := range federatedBundles {
		response.FederatedBundles[federatedBundle.TrustDomain().IDString()] = x509util.ConcatRawCertsFromCerts(federatedBundle.X509Authorities())
	}

	return response
}

func makeX509BundlesResponse(tb testing.TB, bundles ...*x509bundle.Bundle) *brokerpb.SubscribeToX509BundlesResponse {
	tb.Helper()

	response := &brokerpb.SubscribeToX509BundlesResponse{
		Bundles: make(map[string][]byte),
	}
	for _, bundle := range bundles {
		response.Bundles[bundle.TrustDomain().IDString()] = x509util.ConcatRawCertsFromCerts(bundle.X509Authorities())
	}
	return response
}

func makeJWTBundlesResponse(tb testing.TB, bundles ...*jwtbundle.Bundle) *brokerpb.SubscribeToJWTBundlesResponse {
	tb.Helper()

	response := &brokerpb.SubscribeToJWTBundlesResponse{
		Bundles: make(map[string][]byte),
	}
	for _, bundle := range bundles {
		bundleBytes, err := bundle.Marshal()
		require.NoError(tb, err)
		response.Bundles[bundle.TrustDomain().IDString()] = bundleBytes
	}
	return response
}

func makeJWTSVIDResponse(svids ...*jwtsvid.SVID) *brokerpb.FetchJWTSVIDResponse {
	response := &brokerpb.FetchJWTSVIDResponse{}
	for _, svid := range svids {
		response.Svids = append(response.Svids, &brokerpb.JWTSVID{
			SpiffeId: svid.ID.String(),
			Svid:     svid.Marshal(),
			Hint:     svid.Hint,
		})
	}
	return response
}

func requireX509SVID(tb testing.TB, source interface {
	GetX509SVID() (*x509svid.SVID, error)
}, expected *x509svid.SVID) {
	tb.Helper()

	actual, err := source.GetX509SVID()
	require.NoError(tb, err)
	require.Equal(tb, expected, actual)
}

func requireX509Bundle(tb testing.TB, source x509bundle.Source, trustDomain spiffeid.TrustDomain, expected *x509bundle.Bundle) {
	tb.Helper()

	actual, err := source.GetX509BundleForTrustDomain(trustDomain)
	require.NoError(tb, err)
	require.Equal(tb, expected, actual)
}

func requireJWTBundle(tb testing.TB, source jwtbundle.Source, trustDomain spiffeid.TrustDomain, expected *jwtbundle.Bundle) {
	tb.Helper()

	actual, err := source.GetJWTBundleForTrustDomain(trustDomain)
	require.NoError(tb, err)
	require.Equal(tb, expected, actual)
}
