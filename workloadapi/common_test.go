package workloadapi_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

func withAddr(api *fakeworkloadapi.WorkloadAPI) workloadapi.SourceOption {
	return workloadapi.WithClientOptions(workloadapi.WithAddr(api.Addr()))
}

func requireBundle(tb testing.TB, source spiffebundle.Source, td spiffeid.TrustDomain, expected *spiffebundle.Bundle) {
	actual, err := source.GetBundleForTrustDomain(td)
	require.NoError(tb, err)
	require.Equal(tb, expected, actual)
}

func requireNoBundle(tb testing.TB, source spiffebundle.Source, td spiffeid.TrustDomain, expected string) {
	bundle, err := source.GetBundleForTrustDomain(td)
	require.EqualError(tb, err, expected, "SPIFFE bundle should not exist")
	require.Nil(tb, bundle)
}

func requireX509Bundle(tb testing.TB, source x509bundle.Source, td spiffeid.TrustDomain, expected *x509bundle.Bundle) {
	actual, err := source.GetX509BundleForTrustDomain(td)
	require.NoError(tb, err)
	require.Equal(tb, expected, actual)
}

func requireNoX509Bundle(tb testing.TB, source x509bundle.Source, td spiffeid.TrustDomain, expected string) {
	bundle, err := source.GetX509BundleForTrustDomain(td)
	require.EqualError(tb, err, expected, "X.509 bundle should not exist")
	require.Nil(tb, bundle)
}

func requireJWTBundle(tb testing.TB, source jwtbundle.Source, td spiffeid.TrustDomain, expected *jwtbundle.Bundle) {
	actual, err := source.GetJWTBundleForTrustDomain(td)
	require.NoError(tb, err)
	require.Equal(tb, expected, actual)
}

func requireNoJWTBundle(tb testing.TB, source jwtbundle.Source, td spiffeid.TrustDomain, expected string) {
	bundle, err := source.GetJWTBundleForTrustDomain(td)
	require.EqualError(tb, err, expected, "JWT bundle should not exist")
	require.Nil(tb, bundle)
}

func requireX509SVID(tb testing.TB, source x509svid.Source, expected *x509svid.SVID) {
	actual, err := source.GetX509SVID()
	require.NoError(tb, err)
	require.Equal(tb, expected, actual)
}
