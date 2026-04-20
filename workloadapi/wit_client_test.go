package workloadapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	witTD    = spiffeid.RequireTrustDomainFromString("example.org")
	witFooID = spiffeid.RequireFromPath(witTD, "/foo")
	witBarID = spiffeid.RequireFromPath(witTD, "/bar")
	witBazID = spiffeid.RequireFromPath(witTD, "/baz")
)

func makeWITKey(t *testing.T) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func makeWITToken(t *testing.T, id spiffeid.ID, signingKey *ecdsa.PrivateKey, cnfKey *ecdsa.PrivateKey, kid string) string {
	cnfJWK := jose.JSONWebKey{
		Key:       cnfKey.Public(),
		KeyID:     kid,
		Algorithm: string(jose.ES256),
	}
	cnfJWKBytes, err := cnfJWK.MarshalJSON()
	require.NoError(t, err)

	var cnfJWKMap map[string]interface{}
	require.NoError(t, json.Unmarshal(cnfJWKBytes, &cnfJWKMap))

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256,
			Key: jose.JSONWebKey{
				Key:   signingKey,
				KeyID: kid,
			},
		},
		(&jose.SignerOptions{}).WithType("wit+jwt"),
	)
	require.NoError(t, err)

	claims := map[string]interface{}{
		"sub": id.String(),
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
		"iat": jwt.NewNumericDate(time.Now()),
		"cnf": map[string]interface{}{
			"jwk": cnfJWKMap,
		},
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func makeWITBundle(t *testing.T, td spiffeid.TrustDomain, key *ecdsa.PrivateKey, kid string) *witbundle.Bundle {
	bundle := witbundle.New(td)
	require.NoError(t, bundle.AddJWTAuthority(kid, key.Public()))
	return bundle
}

func makeWITSVIDProto(t *testing.T, id spiffeid.ID, signingKey *ecdsa.PrivateKey, cnfKey *ecdsa.PrivateKey, kid string, hint string) *workload.WITSVID {
	token := makeWITToken(t, id, signingKey, cnfKey, kid)

	privJWK := jose.JSONWebKey{
		Key:       cnfKey,
		KeyID:     kid,
		Algorithm: string(jose.ES256),
	}
	privJWKBytes, err := privJWK.MarshalJSON()
	require.NoError(t, err)

	return &workload.WITSVID{
		SpiffeId:   id.String(),
		WitSvid:    token,
		WitSvidKey: string(privJWKBytes),
		Hint:       hint,
	}
}

func newWITClient(t *testing.T, wl *fakeworkloadapi.WorkloadAPI) *workloadapi.Client {
	c, err := workloadapi.New(context.Background(), workloadapi.WithAddr(wl.Addr()))
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}

func TestFetchWITSVID(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()

	key := makeWITKey(t)
	cnfKey := makeWITKey(t)
	kid := "key1"

	wl.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, cnfKey, kid, ""),
			makeWITSVIDProto(t, witBarID, key, cnfKey, kid, ""),
		},
	})

	c := newWITClient(t, wl)
	svid, err := c.FetchWITSVID(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, witFooID, svid.ID)
	assert.NotNil(t, svid.PublicKey)
	assert.NotNil(t, svid.PrivateKey)
	assert.Equal(t, kid, svid.KeyID)
}

func TestFetchWITSVIDs(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()

	key := makeWITKey(t)
	kid := "key1"

	wl.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, makeWITKey(t), kid, "internal"),
			makeWITSVIDProto(t, witBarID, key, makeWITKey(t), kid, "external"),
			makeWITSVIDProto(t, witBazID, key, makeWITKey(t), kid, "internal"), // duplicate hint
		},
	})

	c := newWITClient(t, wl)
	svids, err := c.FetchWITSVIDs(context.Background(), "")
	require.NoError(t, err)
	// witBazID should be skipped due to duplicate hint "internal"
	require.Len(t, svids, 2)
	assert.Equal(t, witFooID, svids[0].ID)
	assert.Equal(t, witBarID, svids[1].ID)
}

func TestFetchWITSVIDs_EmptyHintNotDeduped(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()

	key := makeWITKey(t)
	kid := "key1"

	wl.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, makeWITKey(t), kid, ""),
			makeWITSVIDProto(t, witBarID, key, makeWITKey(t), kid, ""),
		},
	})

	c := newWITClient(t, wl)
	svids, err := c.FetchWITSVIDs(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, svids, 2)
}

func TestFetchWITBundles(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()

	key := makeWITKey(t)
	kid := "key1"
	bundle := makeWITBundle(t, witTD, key, kid)
	wl.SetWITBundles(bundle)

	c := newWITClient(t, wl)
	bundleSet, err := c.FetchWITBundles(context.Background())
	require.NoError(t, err)

	b, ok := bundleSet.Get(witTD)
	require.True(t, ok)
	authority, ok := b.FindJWTAuthority(kid)
	require.True(t, ok)
	assert.NotNil(t, authority)
}

func TestWatchWITSVIDs(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()

	key := makeWITKey(t)
	kid := "key1"

	wl.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, makeWITKey(t), kid, ""),
		},
	})

	c := newWITClient(t, wl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	updateCh := make(chan []*witsvid.SVID, 2)
	watcher := &testWITSVIDWatcher{updateCh: updateCh}

	go func() {
		_ = c.WatchWITSVIDs(ctx, watcher, "")
	}()

	select {
	case svids := <-updateCh:
		require.Len(t, svids, 1)
		assert.Equal(t, witFooID, svids[0].ID)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial WIT-SVID update")
	}

	wl.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witBarID, key, makeWITKey(t), kid, ""),
		},
	})

	select {
	case svids := <-updateCh:
		require.Len(t, svids, 1)
		assert.Equal(t, witBarID, svids[0].ID)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for second WIT-SVID update")
	}
}

func TestWatchWITBundles(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()

	key := makeWITKey(t)
	kid := "key1"

	wl.SetWITBundles(makeWITBundle(t, witTD, key, kid))

	c := newWITClient(t, wl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	updateCh := make(chan *witbundle.Set, 2)
	watcher := &testWITBundleWatcher{updateCh: updateCh}

	go func() {
		_ = c.WatchWITBundles(ctx, watcher)
	}()

	select {
	case bundleSet := <-updateCh:
		require.True(t, bundleSet.Has(witTD))
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial WIT bundle update")
	}
}

func TestWatchWITSVIDs_Unimplemented(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	defer wl.Stop()

	c := newWITClient(t, wl)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	watcher := &testWITSVIDWatcher{updateCh: make(chan []*witsvid.SVID, 1)}
	err := c.WatchWITSVIDs(ctx, watcher, "")
	assert.Error(t, err)
}

type testWITSVIDWatcher struct {
	updateCh chan []*witsvid.SVID
}

func (w *testWITSVIDWatcher) OnWITSVIDsUpdate(svids []*witsvid.SVID) {
	select {
	case w.updateCh <- svids:
	default:
	}
}

func (w *testWITSVIDWatcher) OnWITSVIDsWatchError(error) {}

type testWITBundleWatcher struct {
	updateCh chan *witbundle.Set
}

func (w *testWITBundleWatcher) OnWITBundlesUpdate(bundles *witbundle.Set) {
	select {
	case w.updateCh <- bundles:
	default:
	}
}

func (w *testWITBundleWatcher) OnWITBundlesWatchError(error) {}
