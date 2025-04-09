package workloadapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTSourceDoesNotReturnUntilInitialUpdate(t *testing.T) {
	api := fakeworkloadapi.New(t)
	defer api.Stop()

	// Using a timeout here to detect that it doesn't return isn't ideal. Not
	// sure how to deterministically test it otherwise.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
	defer cancel()

	// Create the source. It will wait for the initial response.
	source, err := workloadapi.NewJWTSource(ctx, withAddr(api))
	if !assert.EqualError(t, err, context.DeadlineExceeded.Error()) {
		source.Close()
	}
}

func TestJWTSourceFailsCallsIfClosed(t *testing.T) {
	// Time out the test after a minute if something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)

	// Set the initial response
	api.SetJWTBundles(ca.JWTBundle())

	// Create the source. It will wait for the initial response.
	source, err := workloadapi.NewJWTSource(ctx, withAddr(api))
	require.NoError(t, err)

	// Close the source
	require.NoError(t, source.Close())

	_, err = source.FetchJWTSVID(ctx, jwtsvid.Params{})
	require.EqualError(t, err, "jwtsource: source is closed")

	_, err = source.GetJWTBundleForTrustDomain(td)
	require.EqualError(t, err, "jwtsource: source is closed")
}

func TestJWTSourceGetsUpdates(t *testing.T) {
	// Time out the test after a minute if something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	// Set up the CA for a few trust domains
	domain1TD := spiffeid.RequireTrustDomainFromString("domain1.test")
	domain1CA := test.NewCA(t, domain1TD)
	domain1Bundle := domain1CA.JWTBundle()

	domain2TD := spiffeid.RequireTrustDomainFromString("domain2.test")
	domain2CA := test.NewCA(t, domain2TD)
	domain2Bundle := domain2CA.JWTBundle()

	// Set the initial response
	api.SetJWTBundles(domain1CA.JWTBundle())

	// Create the source. It will wait for the initial response.
	source, err := workloadapi.NewJWTSource(ctx, withAddr(api))
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, source.Close())
	}()

	// Assert that the bundle for domain1.test is available but not domain2.test.
	requireJWTBundle(t, source, domain1TD, domain1Bundle)
	requireNoJWTBundle(t, source, domain2TD, `jwtbundle: no JWT bundle for trust domain "domain2.test"`)

	// Set a new response
	api.SetJWTBundles(domain2CA.JWTBundle())

	// Wait for the source to be updated with the new response.
	require.NoError(t, source.WaitUntilUpdated(ctx))

	// Assert that the bundle for domain1.test is no longer available and that
	// the bundle domain2.test is now available.
	requireNoJWTBundle(t, source, domain1TD, `jwtbundle: no JWT bundle for trust domain "domain1.test"`)
	requireJWTBundle(t, source, domain2TD, domain2Bundle)
}
