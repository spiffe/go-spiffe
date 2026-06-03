package workloadapi_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	witTD    = spiffeid.RequireTrustDomainFromString("example.org")
	witFooID = spiffeid.RequireFromPath(witTD, "/foo")
	witBarID = spiffeid.RequireFromPath(witTD, "/bar")
	witBazID = spiffeid.RequireFromPath(witTD, "/baz")
)

func TestFetchWITSVID(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	t.Cleanup(wl.Stop)

	key := test.NewEC256Key(t)
	cnfKey := test.NewEC256Key(t)
	kid := "key1"

	wl.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, cnfKey, kid, ""),
			makeWITSVIDProto(t, witBarID, key, cnfKey, kid, ""),
		},
	})

	c := newWITClient(t, wl)
	svid, err := c.FetchWITSVID(t.Context(), "")
	require.NoError(t, err)
	assert.Equal(t, witFooID, svid.ID)
	assert.NotNil(t, svid.PublicKey)
	assert.NotNil(t, svid.PrivateKey)
	assert.Equal(t, kid, svid.KeyID)
}

func TestFetchWITSVIDs(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	t.Cleanup(wl.Stop)

	key := test.NewEC256Key(t)
	kid := "key1"

	wl.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, test.NewEC256Key(t), kid, "internal"),
			makeWITSVIDProto(t, witBarID, key, test.NewEC256Key(t), kid, "external"),
			makeWITSVIDProto(t, witBazID, key, test.NewEC256Key(t), kid, "internal"), // duplicate hint
		},
	})

	c := newWITClient(t, wl)
	svids, err := c.FetchWITSVIDs(t.Context(), "")
	require.NoError(t, err)
	// witBazID should be skipped due to duplicate hint "internal"
	require.Len(t, svids, 2)
	assert.Equal(t, witFooID, svids[0].ID)
	assert.Equal(t, witBarID, svids[1].ID)
}

func TestFetchWITSVIDs_EmptyHintNotDeduped(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	t.Cleanup(wl.Stop)

	key := test.NewEC256Key(t)
	kid := "key1"

	wl.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, test.NewEC256Key(t), kid, ""),
			makeWITSVIDProto(t, witBarID, key, test.NewEC256Key(t), kid, ""),
		},
	})

	c := newWITClient(t, wl)
	svids, err := c.FetchWITSVIDs(t.Context(), "")
	require.NoError(t, err)
	require.Len(t, svids, 2)
}

func TestFetchWITBundles(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	t.Cleanup(wl.Stop)

	key := test.NewEC256Key(t)
	kid := "key1"
	wl.SetWITBundles(makeWITBundle(t, witTD, key, kid))

	c := newWITClient(t, wl)
	bundleSet, err := c.FetchWITBundles(t.Context())
	require.NoError(t, err)

	b, ok := bundleSet.Get(witTD)
	require.True(t, ok)
	authority, ok := b.FindWITAuthority(kid)
	require.True(t, ok)
	assert.NotNil(t, authority)
}

func TestWatchWITSVIDs(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	t.Cleanup(wl.Stop)

	key := test.NewEC256Key(t)
	kid := "key1"

	wl.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, test.NewEC256Key(t), kid, ""),
		},
	})

	c := newWITClient(t, wl)
	updateCh := make(chan []*witsvid.SVID, 2)
	watcher := &testWITSVIDWatcher{updateCh: updateCh}

	go func() {
		_ = c.WatchWITSVIDs(t.Context(), watcher, "")
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
			makeWITSVIDProto(t, witBarID, key, test.NewEC256Key(t), kid, ""),
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
	t.Cleanup(wl.Stop)

	key := test.NewEC256Key(t)
	kid := "key1"

	wl.SetWITBundles(makeWITBundle(t, witTD, key, kid))

	c := newWITClient(t, wl)
	updateCh := make(chan *witbundle.Set, 2)
	watcher := &testWITBundleWatcher{updateCh: updateCh}

	go func() {
		_ = c.WatchWITBundles(t.Context(), watcher)
	}()

	select {
	case bundleSet := <-updateCh:
		require.True(t, bundleSet.Has(witTD))
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial WIT bundle update")
	}
}

func TestWatch_Unimplemented(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeworkloadapi.WorkloadAPI)
		watch func(context.Context, *workloadapi.Client) error
	}{
		{
			name: "WatchWITSVIDs",
			setup: func(wl *fakeworkloadapi.WorkloadAPI) {
				wl.SetWITSVIDError(status.Error(codes.Unimplemented, "WIT-SVID profile not supported"))
			},
			watch: func(ctx context.Context, c *workloadapi.Client) error {
				return c.WatchWITSVIDs(ctx, &testWITSVIDWatcher{updateCh: make(chan []*witsvid.SVID, 1)}, "")
			},
		},
		{
			name: "WatchWITBundles",
			setup: func(wl *fakeworkloadapi.WorkloadAPI) {
				wl.SetWITBundlesError(status.Error(codes.Unimplemented, "WIT bundle profile not supported"))
			},
			watch: func(ctx context.Context, c *workloadapi.Client) error {
				return c.WatchWITBundles(ctx, &testWITBundleWatcher{updateCh: make(chan *witbundle.Set, 1)})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wl := fakeworkloadapi.New(t)
			t.Cleanup(wl.Stop)
			tt.setup(wl)
			err := tt.watch(t.Context(), newWITClient(t, wl))
			require.Error(t, err)
			assert.Equal(t, codes.Unimplemented, status.Code(err))
		})
	}
}

func TestFetchWITSVID_PackageLevel(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	t.Cleanup(wl.Stop)
	key := test.NewEC256Key(t)
	kid := "key1"
	wl.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, test.NewEC256Key(t), kid, ""),
		},
	})
	svid, err := workloadapi.FetchWITSVID(t.Context(), "", workloadapi.WithAddr(wl.Addr()))
	require.NoError(t, err)
	assert.Equal(t, witFooID, svid.ID)
}

func TestFetchWITSVIDs_PackageLevel(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	t.Cleanup(wl.Stop)
	key := test.NewEC256Key(t)
	kid := "key1"
	wl.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, test.NewEC256Key(t), kid, ""),
			makeWITSVIDProto(t, witBarID, key, test.NewEC256Key(t), kid, ""),
		},
	})
	svids, err := workloadapi.FetchWITSVIDs(t.Context(), "", workloadapi.WithAddr(wl.Addr()))
	require.NoError(t, err)
	require.Len(t, svids, 2)
	assert.Equal(t, witFooID, svids[0].ID)
	assert.Equal(t, witBarID, svids[1].ID)
}

func TestFetchWITBundles_PackageLevel(t *testing.T) {
	wl := fakeworkloadapi.New(t)
	t.Cleanup(wl.Stop)
	key := test.NewEC256Key(t)
	kid := "key1"
	wl.SetWITBundles(makeWITBundle(t, witTD, key, kid))
	bundleSet, err := workloadapi.FetchWITBundles(t.Context(), workloadapi.WithAddr(wl.Addr()))
	require.NoError(t, err)
	assert.True(t, bundleSet.Has(witTD))
}

func TestFetchWITSVIDs_PrivateKeyErrors(t *testing.T) {
	key := test.NewEC256Key(t)
	cnfKey := test.NewEC256Key(t)
	const kid = "key1"

	pubJWK := jose.JSONWebKey{Key: cnfKey.Public(), KeyID: kid, Algorithm: string(jose.ES256)}
	pubJWKBytes, err := pubJWK.MarshalJSON()
	require.NoError(t, err)

	tests := []struct {
		name    string
		witKey  string
		wantErr string
	}{
		{
			name:    "malformed JWK",
			witKey:  "not-a-jwk",
			wantErr: "unable to parse private key JWK",
		},
		{
			name:    "public key instead of private",
			witKey:  string(pubJWKBytes),
			wantErr: "expected private key JWK, got public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wl := fakeworkloadapi.New(t)
			t.Cleanup(wl.Stop)

			proto := makeWITSVIDProto(t, witFooID, key, cnfKey, kid, "")
			proto.WitSvidKey = tt.witKey
			wl.SetWITSVIDResponse(&workload.WITSVIDResponse{Svids: []*workload.WITSVID{proto}})

			_, err := newWITClient(t, wl).FetchWITSVIDs(t.Context(), "")
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
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

func makeWITToken(t *testing.T, id spiffeid.ID, signingKey *ecdsa.PrivateKey, cnfKey *ecdsa.PrivateKey, kid string) string {
	t.Helper()
	cnfJWK := jose.JSONWebKey{
		Key:       cnfKey.Public(),
		KeyID:     kid,
		Algorithm: string(jose.ES256),
	}
	cnfJWKBytes, err := cnfJWK.MarshalJSON()
	require.NoError(t, err)

	var cnfJWKMap map[string]any
	require.NoError(t, json.Unmarshal(cnfJWKBytes, &cnfJWKMap))

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       jose.JSONWebKey{Key: signingKey, KeyID: kid},
		},
		(&jose.SignerOptions{}).WithType("wit+jwt"),
	)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(map[string]any{
		"sub": id.String(),
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
		"iat": jwt.NewNumericDate(time.Now()),
		"cnf": map[string]any{"jwk": cnfJWKMap},
	}).Serialize()
	require.NoError(t, err)
	return token
}

func makeWITBundle(t *testing.T, td spiffeid.TrustDomain, key *ecdsa.PrivateKey, kid string) *witbundle.Bundle {
	t.Helper()
	bundle := witbundle.New(td)
	require.NoError(t, bundle.AddWITAuthority(kid, key.Public()))
	return bundle
}

func makeWITSVIDProto(t *testing.T, id spiffeid.ID, signingKey *ecdsa.PrivateKey, cnfKey *ecdsa.PrivateKey, kid string, hint string) *workload.WITSVID {
	t.Helper()
	privJWK := jose.JSONWebKey{Key: cnfKey, KeyID: kid, Algorithm: string(jose.ES256)}
	privJWKBytes, err := privJWK.MarshalJSON()
	require.NoError(t, err)
	return &workload.WITSVID{
		SpiffeId:   id.String(),
		WitSvid:    makeWITToken(t, id, signingKey, cnfKey, kid),
		WitSvidKey: string(privJWKBytes),
		Hint:       hint,
	}
}

func newWITClient(t *testing.T, wl *fakeworkloadapi.WorkloadAPI) *workloadapi.Client {
	t.Helper()
	c, err := workloadapi.New(t.Context(), workloadapi.WithAddr(wl.Addr()))
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}
