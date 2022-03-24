package workloadapi

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	td          = spiffeid.RequireTrustDomainFromString("example.org")
	federatedTD = spiffeid.RequireTrustDomainFromString("federated.test")
	fooID       = spiffeid.RequireFromPath(td, "/foo")
	barID       = spiffeid.RequireFromPath(td, "/bar")
	bazID       = spiffeid.RequireFromPath(td, "/baz")
)

func TestFetchX509SVID(t *testing.T) {
	ca := test.NewCA(t, td)
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()
	c, err := New(context.Background(), WithAddr(wl.Addr()))
	require.NoError(t, err)
	defer c.Close()

	resp := &fakeworkloadapi.X509SVIDResponse{
		Bundle: ca.X509Bundle(),
		SVIDs:  makeX509SVIDs(ca, fooID, barID),
	}

	wl.SetX509SVIDResponse(resp)
	svid, err := c.FetchX509SVID(context.Background())

	require.NoError(t, err)
	assertX509SVID(t, svid, fooID, resp.SVIDs[0].Certificates)
}

func TestFetchX509SVIDs(t *testing.T) {
	ca := test.NewCA(t, td)
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()
	c, err := New(context.Background(), WithAddr(wl.Addr()))
	require.NoError(t, err)
	defer c.Close()

	resp := &fakeworkloadapi.X509SVIDResponse{
		Bundle: ca.X509Bundle(),
		SVIDs:  makeX509SVIDs(ca, fooID, barID),
	}
	wl.SetX509SVIDResponse(resp)

	svids, err := c.FetchX509SVIDs(context.Background())

	require.NoError(t, err)
	require.Len(t, svids, 2)
	assertX509SVID(t, svids[0], fooID, resp.SVIDs[0].Certificates)
	assertX509SVID(t, svids[1], barID, resp.SVIDs[1].Certificates)
}

func TestFetchX509Bundles(t *testing.T) {
	ca := test.NewCA(t, td)
	federatedCA := test.NewCA(t, federatedTD)
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()
	c, err := New(context.Background(), WithAddr(wl.Addr()))
	require.NoError(t, err)
	defer c.Close()

	svids := makeX509SVIDs(ca, fooID, barID)

	wl.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		Bundle:           ca.X509Bundle(),
		SVIDs:            svids,
		FederatedBundles: []*x509bundle.Bundle{federatedCA.X509Bundle()},
	})

	bundles, err := c.FetchX509Bundles(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 2, bundles.Len())
	assertX509Bundle(t, bundles, td, ca.X509Bundle())
	assertX509Bundle(t, bundles, federatedTD, federatedCA.X509Bundle())

	// Now set the next response without any bundles and assert that the call
	// fails since the bundle cannot be empty.
	wl.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs: svids,
	})

	bundles, err = c.FetchX509Bundles(context.Background())

	require.EqualError(t, err, `empty X.509 bundle for trust domain "example.org"`)
	require.Nil(t, bundles)
}

func TestFetchX509Context(t *testing.T) {
	ca := test.NewCA(t, td)
	federatedCA := test.NewCA(t, federatedTD)
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()
	c, err := New(context.Background(), WithAddr(wl.Addr()))
	require.NoError(t, err)
	defer c.Close()

	svids := makeX509SVIDs(ca, fooID, barID)

	resp := &fakeworkloadapi.X509SVIDResponse{
		Bundle:           ca.X509Bundle(),
		SVIDs:            svids,
		FederatedBundles: []*x509bundle.Bundle{federatedCA.X509Bundle()},
	}
	wl.SetX509SVIDResponse(resp)

	x509Ctx, err := c.FetchX509Context(context.Background())

	require.NoError(t, err)
	// inspect svids
	require.Len(t, x509Ctx.SVIDs, 2)
	assertX509SVID(t, x509Ctx.SVIDs[0], fooID, resp.SVIDs[0].Certificates)
	assertX509SVID(t, x509Ctx.SVIDs[1], barID, resp.SVIDs[1].Certificates)

	// inspect bundles
	assert.Equal(t, 2, x509Ctx.Bundles.Len())
	assertX509Bundle(t, x509Ctx.Bundles, td, ca.X509Bundle())
	assertX509Bundle(t, x509Ctx.Bundles, federatedTD, federatedCA.X509Bundle())

	// Now set the next response without any bundles and assert that the call
	// fails since the bundle cannot be empty.
	wl.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs: svids,
	})

	x509Ctx, err = c.FetchX509Context(context.Background())

	require.EqualError(t, err, `empty X.509 bundle for trust domain "example.org"`)
	require.Nil(t, x509Ctx)
}

func TestWatchX509Context(t *testing.T) {
	ca := test.NewCA(t, td)
	federatedCA := test.NewCA(t, federatedTD)
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()
	c, err := New(context.Background(), WithAddr(wl.Addr()))
	require.NoError(t, err)
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
	require.Len(t, tw.Errors(), 1)
	require.Len(t, tw.X509Contexts(), 0)

	// test first update
	resp := &fakeworkloadapi.X509SVIDResponse{
		Bundle:           ca.X509Bundle(),
		SVIDs:            makeX509SVIDs(ca, fooID, barID),
		FederatedBundles: []*x509bundle.Bundle{federatedCA.X509Bundle()},
	}
	wl.SetX509SVIDResponse(resp)

	tw.WaitForUpdates(1)

	require.Len(t, tw.Errors(), 1)
	require.Len(t, tw.X509Contexts(), 1)
	update := tw.X509Contexts()[len(tw.X509Contexts())-1]
	// inspect svids
	require.Len(t, update.SVIDs, 2)
	assertX509SVID(t, update.SVIDs[0], fooID, resp.SVIDs[0].Certificates)
	assertX509SVID(t, update.SVIDs[1], barID, resp.SVIDs[1].Certificates)
	// inspect bundles
	assert.Equal(t, 2, update.Bundles.Len())
	assertX509Bundle(t, update.Bundles, td, ca.X509Bundle())
	assertX509Bundle(t, update.Bundles, federatedTD, federatedCA.X509Bundle())

	// test second update
	resp = &fakeworkloadapi.X509SVIDResponse{
		Bundle: ca.X509Bundle(),
		SVIDs:  makeX509SVIDs(ca, bazID),
	}

	wl.SetX509SVIDResponse(resp)

	tw.WaitForUpdates(1)

	require.Len(t, tw.Errors(), 1)
	require.Len(t, tw.X509Contexts(), 2)
	update = tw.X509Contexts()[len(tw.X509Contexts())-1]
	// inspect svids
	require.Len(t, update.SVIDs, 1)
	assertX509SVID(t, update.SVIDs[0], bazID, resp.SVIDs[0].Certificates)
	// inspect bundles
	assert.Equal(t, 1, update.Bundles.Len())
	assertX509Bundle(t, update.Bundles, td, ca.X509Bundle())

	// test error
	wl.Stop()
	tw.WaitForUpdates(1)
	assert.Len(t, tw.Errors(), 2)

	cancel()
	wg.Wait()
}

func TestFetchJWTSVID(t *testing.T) {
	ca := test.NewCA(t, td)
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()
	c, _ := New(context.Background(), WithAddr(wl.Addr()))
	defer c.Close()

	subjectID := spiffeid.RequireFromPath(td, "/subject")
	audienceID := spiffeid.RequireFromPath(td, "/audience")
	extraAudienceID := spiffeid.RequireFromPath(td, "/extra_audience")
	token := ca.CreateJWTSVID(subjectID, []string{audienceID.String(), extraAudienceID.String()}).Marshal()
	respJWT := makeJWTSVIDResponse(ca, []string{token}, subjectID)
	wl.SetJWTSVIDResponse(respJWT)

	params := jwtsvid.Params{
		Subject:        subjectID,
		Audience:       audienceID.String(),
		ExtraAudiences: []string{extraAudienceID.String()},
	}

	jwtSvid, err := c.FetchJWTSVID(context.Background(), params)

	require.NoError(t, err)
	assertJWTSVID(t, jwtSvid, subjectID, token, audienceID.String(), extraAudienceID.String())
}

func TestFetchJWTSVIDs(t *testing.T) {
	ca := test.NewCA(t, td)
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()
	c, _ := New(context.Background(), WithAddr(wl.Addr()))
	defer c.Close()

	subjectID := spiffeid.RequireFromPath(td, "/subject")
	extraSubjectID := spiffeid.RequireFromPath(td, "/extra_subject")
	audienceID := spiffeid.RequireFromPath(td, "/audience")
	extraAudienceID := spiffeid.RequireFromPath(td, "/extra_audience")
	subjectIDToken := ca.CreateJWTSVID(subjectID, []string{audienceID.String(), extraAudienceID.String()}).Marshal()
	extraSubjectIDToken := ca.CreateJWTSVID(extraSubjectID, []string{audienceID.String(), extraAudienceID.String()}).Marshal()
	respJWT := makeJWTSVIDResponse(ca, []string{subjectIDToken, extraSubjectIDToken}, subjectID, extraSubjectID)
	wl.SetJWTSVIDResponse(respJWT)

	params := jwtsvid.Params{
		Subject:        subjectID,
		Audience:       audienceID.String(),
		ExtraAudiences: []string{extraAudienceID.String()},
	}

	jwtSvid, err := c.FetchJWTSVIDs(context.Background(), params)

	require.NoError(t, err)
	assertJWTSVID(t, jwtSvid[0], subjectID, subjectIDToken, audienceID.String(), extraAudienceID.String())
	assertJWTSVID(t, jwtSvid[1], extraSubjectID, extraSubjectIDToken, audienceID.String(), extraAudienceID.String())
}

func TestFetchJWTBundles(t *testing.T) {
	ca := test.NewCA(t, td)
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()
	c, err := New(context.Background(), WithAddr(wl.Addr()))
	require.NoError(t, err)
	defer c.Close()

	wl.SetJWTBundles(ca.JWTBundle())

	bundleSet, err := c.FetchJWTBundles(context.Background())

	require.NoError(t, err)
	assertJWTBundle(t, bundleSet, td, ca.JWTBundle())
}

func TestWatchJWTBundles(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()
	c, err := New(context.Background(), WithAddr(wl.Addr()))
	require.NoError(t, err)
	defer c.Close()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tw := newTestWatcher(t)
	wg.Add(1)
	go func() {
		_ = c.WatchJWTBundles(ctx, tw)
		wg.Done()
	}()

	// test PermissionDenied
	tw.WaitForUpdates(1)
	require.Len(t, tw.Errors(), 1)
	require.Len(t, tw.JwtBundles(), 0)

	// test first update
	ca1 := test.NewCA(t, td)
	wl.SetJWTBundles(ca1.JWTBundle())

	tw.WaitForUpdates(1)

	require.Len(t, tw.Errors(), 1)
	update := tw.JwtBundles()[len(tw.JwtBundles())-1]
	assertJWTBundle(t, update, td, ca1.JWTBundle())

	// test second update
	ca2 := test.NewCA(t, td)
	wl.SetJWTBundles(ca2.JWTBundle())

	tw.WaitForUpdates(1)

	require.Len(t, tw.Errors(), 1)
	update = tw.JwtBundles()[len(tw.JwtBundles())-1]
	assertJWTBundle(t, update, td, ca2.JWTBundle())

	// test error
	wl.Stop()
	tw.WaitForUpdates(1)
	assert.Len(t, tw.Errors(), 2)
}

func TestValidateJWTSVID(t *testing.T) {
	ca := test.NewCA(t, td)
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()
	c, err := New(context.Background(), WithAddr(wl.Addr()))
	require.NoError(t, err)
	defer c.Close()

	workloadID := spiffeid.RequireFromPath(td, "/workload")
	audience := []string{"spiffe://example.org/me", "spiffe://example.org/me_too"}
	token := ca.CreateJWTSVID(workloadID, audience)

	t.Run("first audience is valid", func(t *testing.T) {
		jwtSvid, err := c.ValidateJWTSVID(context.Background(), token.Marshal(), audience[0])

		assert.NoError(t, err)
		assertJWTSVID(t, jwtSvid, workloadID, token.Marshal(), audience...)
	})

	t.Run("second audience is valid", func(t *testing.T) {
		jwtSvid, err := c.ValidateJWTSVID(context.Background(), token.Marshal(), audience[1])

		assert.NoError(t, err)
		assertJWTSVID(t, jwtSvid, workloadID, token.Marshal(), audience...)
	})

	t.Run("invalid audience returns error", func(t *testing.T) {
		jwtSvid, err := c.ValidateJWTSVID(context.Background(), token.Marshal(), "spiffe://example.org/not_me")

		assert.NotNil(t, err)
		assert.Nil(t, jwtSvid)
	})
}

func makeX509SVIDs(ca *test.CA, ids ...spiffeid.ID) []*x509svid.SVID {
	svids := []*x509svid.SVID{}
	for _, id := range ids {
		svids = append(svids, ca.CreateX509SVID(id))
	}
	return svids
}

func makeJWTSVIDResponse(ca *test.CA, token []string, ids ...spiffeid.ID) *workload.JWTSVIDResponse {
	svids := []*workload.JWTSVID{}
	for i, id := range ids {
		svid := &workload.JWTSVID{
			SpiffeId: id.String(),
			Svid:     token[i],
		}
		svids = append(svids, svid)
	}
	return &workload.JWTSVIDResponse{
		Svids: svids,
	}
}

func assertX509SVID(tb testing.TB, svid *x509svid.SVID, spiffeID spiffeid.ID, certificates []*x509.Certificate) {
	assert.Equal(tb, spiffeID, svid.ID)
	assert.Equal(tb, certificates, svid.Certificates)
	assert.NotEmpty(tb, svid.PrivateKey)
}

func assertX509Bundle(tb testing.TB, bundleSet *x509bundle.Set, trustDomain spiffeid.TrustDomain, expectedBundle *x509bundle.Bundle) {
	b, ok := bundleSet.Get(trustDomain)
	require.True(tb, ok)
	assert.Equal(tb, b, expectedBundle)
}

func assertJWTBundle(tb testing.TB, bundleSet *jwtbundle.Set, trustDomain spiffeid.TrustDomain, expectedBundle *jwtbundle.Bundle) {
	b, ok := bundleSet.Get(trustDomain)
	require.True(tb, ok)
	assert.Equal(tb, b, expectedBundle)
}

func assertJWTSVID(t testing.TB, jwtSvid *jwtsvid.SVID, subjectID spiffeid.ID, token string, audience ...string) {
	assert.Equal(t, subjectID.String(), jwtSvid.ID.String())
	assert.Equal(t, audience, jwtSvid.Audience)
	assert.NotNil(t, jwtSvid.Claims)
	assert.NotEmpty(t, jwtSvid.Expiry)
	assert.Equal(t, token, jwtSvid.Marshal())
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
