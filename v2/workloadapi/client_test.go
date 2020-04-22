package workloadapi

import (
	"context"
	"crypto"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchX509SVID(t *testing.T) {
	ca := test.NewCA(t)
	wl := fakeworkloadapi.NewWorkloadAPI(t)
	defer wl.Stop()
	c, _ := New(context.TODO(), WithAddr(wl.Addr()))
	defer c.Close()
	resp := &fakeworkloadapi.X509SVIDResponse{
		Bundle: ca.Roots(),
		SVIDs:  makeX509SVIDs([]string{"spiffe://example.org/foo", "spiffe://example.org/bar"}, ca),
	}
	wl.SetX509SVIDResponse(resp)
	svid, err := c.FetchX509SVID(context.TODO())

	assert.Nil(t, err)
	assert.Equal(t, "spiffe://example.org/foo", svid.ID.String())
	assert.Len(t, svid.Certificates, 1)
	assert.NotEmpty(t, svid.PrivateKey)
}

func TestFetchX509SVIDs(t *testing.T) {
	ca := test.NewCA(t)
	wl := fakeworkloadapi.NewWorkloadAPI(t)
	defer wl.Stop()
	c, _ := New(context.TODO(), WithAddr(wl.Addr()))
	defer c.Close()

	resp := &fakeworkloadapi.X509SVIDResponse{
		Bundle: ca.Roots(),
		SVIDs:  makeX509SVIDs([]string{"spiffe://example.org/foo", "spiffe://example.org/bar"}, ca),
	}
	wl.SetX509SVIDResponse(resp)

	svids, err := c.FetchX509SVIDs(context.TODO())
	assert.Nil(t, err)
	assert.Len(t, svids, 2)
	assert.Equal(t, "spiffe://example.org/foo", svids[0].ID.String())
}

func TestFetchX509Bundles(t *testing.T) {
	ca := test.NewCA(t)
	federatedCA := test.NewCA(t)
	wl := fakeworkloadapi.NewWorkloadAPI(t)
	defer wl.Stop()
	c, _ := New(context.TODO(), WithAddr(wl.Addr()))
	defer c.Close()

	resp := &fakeworkloadapi.X509SVIDResponse{
		Bundle:           ca.Roots(),
		SVIDs:            makeX509SVIDs([]string{"spiffe://example.org/foo", "spiffe://example.org/bar"}, ca),
		FederatedBundles: map[string][]*x509.Certificate{"spiffe://federated.org": federatedCA.Roots()},
	}
	wl.SetX509SVIDResponse(resp)

	bundles, err := c.FetchX509Bundles(context.TODO())
	assert.Nil(t, err)
	assert.Len(t, bundles.Bundles(), 2)
}

func TestFetchX509Context(t *testing.T) {
	ca := test.NewCA(t)
	federatedCA := test.NewCA(t)
	wl := fakeworkloadapi.NewWorkloadAPI(t)
	defer wl.Stop()
	c, _ := New(context.TODO(), WithAddr(wl.Addr()))
	defer c.Close()

	resp := &fakeworkloadapi.X509SVIDResponse{
		Bundle:           ca.Roots(),
		SVIDs:            makeX509SVIDs([]string{"spiffe://example.org/foo", "spiffe://example.org/bar"}, ca),
		FederatedBundles: map[string][]*x509.Certificate{"spiffe://federated.org": federatedCA.Roots()},
	}
	wl.SetX509SVIDResponse(resp)

	x509Ctx, err := c.FetchX509Context(context.TODO())
	assert.Nil(t, err)
	assert.Len(t, x509Ctx.SVIDs, 2)
	assert.Len(t, x509Ctx.Bundles.Bundles(), 2)
}

func TestWatchX509Context(t *testing.T) {
	ca := test.NewCA(t)
	federatedCA := test.NewCA(t)
	wl := fakeworkloadapi.NewWorkloadAPI(t)
	defer wl.Stop()
	c, _ := New(context.TODO(), WithAddr(wl.Addr()))
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	tw := newTestWatcher(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		_ = c.WatchX509Context(ctx, tw)
		wg.Done()
	}()

	// test PermissionDenied
	tw.WaitForUpdates(1)
	assert.Len(t, tw.Errors(), 1)
	assert.Len(t, tw.X509Contexts(), 0)

	// test first update
	resp := &fakeworkloadapi.X509SVIDResponse{
		Bundle:           ca.Roots(),
		SVIDs:            makeX509SVIDs([]string{"spiffe://example.org/foo", "spiffe://example.org/bar"}, ca),
		FederatedBundles: map[string][]*x509.Certificate{"spiffe://federated.org": federatedCA.Roots()},
	}
	wl.SetX509SVIDResponse(resp)

	tw.WaitForUpdates(1)

	assert.Len(t, tw.Errors(), 1)
	assert.Len(t, tw.X509Contexts(), 1)
	assert.Len(t, tw.X509Contexts()[0].SVIDs, 2)

	// test second update
	resp = &fakeworkloadapi.X509SVIDResponse{
		Bundle:           ca.Roots(),
		SVIDs:            makeX509SVIDs([]string{"spiffe://example.org/baz"}, ca),
		FederatedBundles: map[string][]*x509.Certificate{"spiffe://federated.org": federatedCA.Roots()},
	}
	wl.SetX509SVIDResponse(resp)
	tw.WaitForUpdates(1)

	assert.Len(t, tw.Errors(), 1)
	assert.Len(t, tw.X509Contexts(), 2)
	assert.Len(t, tw.X509Contexts()[0].SVIDs, 2)
	assert.Len(t, tw.X509Contexts()[1].SVIDs, 1)

	// test error
	wl.Stop()
	tw.WaitForUpdates(1)
	assert.Len(t, tw.Errors(), 2)

	cancel()
	wg.Wait()
}

func TestFetchJWTSVID(t *testing.T) {
	ca := test.NewCA(t)
	wl := fakeworkloadapi.NewWorkloadAPI(t)
	c, _ := New(context.TODO(), WithAddr(wl.Addr()))
	defer wl.Stop()
	defer c.Close()

	spiffeID, _ := spiffeid.New("spiffe://example.org", "mytoken")
	audience := []string{"spiffe://example.org/audience", "spiffe://example.org/extra_audience"}
	respJWT := makeJWTSVIDResponse(spiffeID.String(), audience, ca)
	wl.SetJWTSVIDResponse(respJWT)

	params := jwtsvid.Params{
		Subject:        spiffeID,
		Audience:       audience[0],
		ExtraAudiences: []string{"spiffe://example.org/extra_audience"},
	}

	jwtSvid, err := c.FetchJWTSVID(context.TODO(), params)

	assert.Nil(t, err)
	assert.Equal(t, "spiffe://example.org/mytoken", jwtSvid.ID.String())
	assert.Equal(t, audience, jwtSvid.Audience)
	assert.NotNil(t, jwtSvid.Claims)
	assert.NotEmpty(t, jwtSvid.Expiry)
	assert.NotEmpty(t, jwtSvid.Marshal())
}

func TestFetchJWTBundles(t *testing.T) {
	ca := test.NewCA(t)
	wl := fakeworkloadapi.NewWorkloadAPI(t)
	c, _ := New(context.TODO(), WithAddr(wl.Addr()))
	defer wl.Stop()
	defer c.Close()

	jwk1 := ca.PublicJWTKey()
	jwk2 := ca.PublicJWTKey()
	keys := map[string]crypto.PublicKey{
		"1": jwk1,
		"2": jwk2,
	}
	wl.SetJWTBundle("spiffe://example.org", keys)

	bundleSet, err := c.FetchJWTBundles(context.TODO())

	assert.Nil(t, err)
	assert.Equal(t, 1, bundleSet.Len())
	spiffeID, _ := spiffeid.New("spiffe://example.org")
	assert.True(t, bundleSet.Has(spiffeID.TrustDomain()))
	bundle, _ := bundleSet.Get(spiffeID.TrustDomain())
	assert.Len(t, bundle.JWTAuthorities(), 2)
}

func TestWatchJWTBundles(t *testing.T) {
	ca := test.NewCA(t)
	wl := fakeworkloadapi.NewWorkloadAPI(t)
	defer wl.Stop()
	c, _ := New(context.TODO(), WithAddr(wl.Addr()))
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())

	td, _ := spiffeid.TrustDomainFromString("spiffe://example.org")
	tw := newTestWatcher(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		_ = c.WatchJWTBundles(ctx, tw)
		wg.Done()
	}()

	// test PermissionDenied
	tw.WaitForUpdates(1)
	assert.Len(t, tw.Errors(), 1)
	assert.Len(t, tw.JwtBundles(), 0)

	// test first update
	jwk1 := ca.PublicJWTKey()
	keys := map[string]crypto.PublicKey{
		"1": jwk1,
	}
	wl.SetJWTBundle(td.String(), keys)

	tw.WaitForUpdates(1)

	assert.Len(t, tw.Errors(), 1)
	update := tw.JwtBundles()[len(tw.JwtBundles())-1]
	bundle, _ := update.Get(td)
	assert.Len(t, bundle.JWTAuthorities(), 1)
	assert.NotNil(t, bundle.JWTAuthorities()["1"])

	// test second update
	jwk2 := ca.PublicJWTKey()
	keys = map[string]crypto.PublicKey{
		"1": jwk1,
		"2": jwk2,
	}
	wl.SetJWTBundle(td.String(), keys)

	tw.WaitForUpdates(1)

	assert.Len(t, tw.Errors(), 1)
	update = tw.JwtBundles()[len(tw.JwtBundles())-1]
	bundle, _ = update.Get(td)
	assert.Len(t, bundle.JWTAuthorities(), 2)
	assert.NotNil(t, bundle.JWTAuthorities()["1"])
	assert.NotNil(t, bundle.JWTAuthorities()["2"])

	// test error
	wl.Stop()
	tw.WaitForUpdates(1)
	assert.Len(t, tw.Errors(), 2)

	cancel()
	wg.Wait()
}

func TestValidateJWTSVID(t *testing.T) {
	ca := test.NewCA(t)
	wl := fakeworkloadapi.NewWorkloadAPI(t)
	c, _ := New(context.TODO(), WithAddr(wl.Addr()))
	defer wl.Stop()
	defer c.Close()

	audience := []string{"spiffe://example.org/me", "spiffe://example.org/me_too"}
	token := ca.CreateJWTSVID("spiffe://example.org/workload", audience)

	t.Run("first audience is valid", func(t *testing.T) {
		jwtSvid, err := c.ValidateJWTSVID(context.TODO(), token, audience[0])
		assert.Nil(t, err)
		assert.NotNil(t, jwtSvid)
	})

	t.Run("second audience is valid", func(t *testing.T) {
		jwtSvid, err := c.ValidateJWTSVID(context.TODO(), token, audience[1])
		assert.Nil(t, err)
		assert.NotNil(t, jwtSvid)
	})

	t.Run("invalid audience returns error", func(t *testing.T) {
		jwtSvid, err := c.ValidateJWTSVID(context.TODO(), token, "spiffe://example.org/not_me")
		assert.NotNil(t, err)
		assert.Nil(t, jwtSvid)
	})
}

func makeX509SVIDs(spiffeIDs []string, ca *test.CA) []fakeworkloadapi.X509SVID {
	svids := []fakeworkloadapi.X509SVID{}
	for _, id := range spiffeIDs {
		svid, key := ca.CreateX509SVID(id)
		svids = append(svids, fakeworkloadapi.X509SVID{CertChain: svid, Key: key})
	}
	return svids
}

func makeJWTSVIDResponse(spiffeID string, audience []string, ca *test.CA) *workload.JWTSVIDResponse {
	token := ca.CreateJWTSVID(spiffeID, audience)
	svids := []*workload.JWTSVID{
		{
			SpiffeId: spiffeID,
			Svid:     token,
		},
	}
	return &workload.JWTSVIDResponse{
		Svids: svids}
}

type testWatcher struct {
	t            *testing.T
	mu           sync.Mutex
	x509Contexts []*X509Context
	jwtBundles   []*jwtbundle.Set
	errors       []error
	updateSignal chan struct{}
}

func newTestWatcher(t *testing.T) *testWatcher {
	return &testWatcher{
		t:            t,
		updateSignal: make(chan struct{}, 100),
	}
}

func (w *testWatcher) X509Contexts() []*X509Context {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.x509Contexts
}

func (w *testWatcher) JwtBundles() []*jwtbundle.Set {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.jwtBundles
}

func (w *testWatcher) Errors() []error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.errors
}

func (w *testWatcher) OnX509ContextUpdate(u *X509Context) {
	w.mu.Lock()
	w.x509Contexts = append(w.x509Contexts, u)
	w.mu.Unlock()
	w.updateSignal <- struct{}{}
}

func (w *testWatcher) OnX509ContextWatchError(err error) {
	w.mu.Lock()
	w.errors = append(w.errors, err)
	w.mu.Unlock()
	w.updateSignal <- struct{}{}
}
func (w *testWatcher) OnJWTBundlesUpdate(u *jwtbundle.Set) {
	w.mu.Lock()
	w.jwtBundles = append(w.jwtBundles, u)
	w.mu.Unlock()
	w.updateSignal <- struct{}{}
}

func (w *testWatcher) OnJWTBundlesWatchError(err error) {
	w.mu.Lock()
	w.errors = append(w.errors, err)
	w.mu.Unlock()
	w.updateSignal <- struct{}{}
}

func (w *testWatcher) WaitForUpdates(expectedNumUpdates int) {
	numUpdates := 0
	timeoutSignal := time.After(10 * time.Second)
	for {
		select {
		case <-w.updateSignal:
			numUpdates++
		case <-timeoutSignal:
			require.Fail(w.t, "Timeout exceeding waiting for updates.")
		}
		if numUpdates == expectedNumUpdates {
			return
		}
	}
}
