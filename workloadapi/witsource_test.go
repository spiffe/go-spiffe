package workloadapi_test

import (
	"context"
	"testing"
	"time"

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

func TestNewWITSource(t *testing.T) {
	t.Run("blocks until both SVIDs and bundles arrive", func(t *testing.T) {
		api := fakeworkloadapi.New(t)
		t.Cleanup(api.Stop)

		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()

		src, err := workloadapi.NewWITSource(ctx, withAddr(api))
		if !assert.ErrorIs(t, err, context.DeadlineExceeded) {
			if src != nil {
				src.Close()
			}
		}
	})

	t.Run("fails immediately when server returns Unimplemented", func(t *testing.T) {
		api := fakeworkloadapi.New(t)
		t.Cleanup(api.Stop)
		api.SetWITSVIDError(status.Error(codes.Unimplemented, "WIT-SVID profile not supported"))

		_, err := workloadapi.NewWITSource(t.Context(), withAddr(api))
		require.ErrorContains(t, err, "Unimplemented")
	})
}

func TestWITSourceLookup(t *testing.T) {
	api := fakeworkloadapi.New(t)
	t.Cleanup(api.Stop)
	src := witSourceSetup(t, api)

	t.Run("GetWITSVIDForID/found", func(t *testing.T) {
		svid, err := src.GetWITSVIDForID(witFooID)
		require.NoError(t, err)
		assert.Equal(t, witFooID, svid.ID)
	})

	t.Run("GetWITSVIDForID/not found", func(t *testing.T) {
		unknown := spiffeid.RequireFromPath(witTD, "/unknown")
		_, err := src.GetWITSVIDForID(unknown)
		require.EqualError(t, err, `witsource: no WIT-SVID found for SPIFFE ID "spiffe://example.org/unknown"`)
	})

	t.Run("GetWITBundleForTrustDomain/found", func(t *testing.T) {
		bundle, err := src.GetWITBundleForTrustDomain(witTD)
		require.NoError(t, err)
		assert.Equal(t, witTD, bundle.TrustDomain())
	})

	t.Run("GetWITBundleForTrustDomain/not found", func(t *testing.T) {
		_, err := src.GetWITBundleForTrustDomain(spiffeid.RequireTrustDomainFromString("other.org"))
		require.EqualError(t, err, `witbundle: no WIT bundle for trust domain "other.org"`)
	})
}

func TestWITSourceClose(t *testing.T) {
	api := fakeworkloadapi.New(t)
	t.Cleanup(api.Stop)
	src := witSourceSetup(t, api)

	require.NoError(t, src.Close())

	t.Run("post-close calls return error", func(t *testing.T) {
		_, err := src.GetWITSVIDForID(witFooID)
		require.EqualError(t, err, "witsource: source is closed")

		_, err = src.GetWITBundleForTrustDomain(witTD)
		require.EqualError(t, err, "witsource: source is closed")
	})

	t.Run("idempotent", func(t *testing.T) {
		require.NoError(t, src.Close())
	})
}

func TestWITSourceGetsUpdates(t *testing.T) {
	api := fakeworkloadapi.New(t)
	t.Cleanup(api.Stop)

	key := test.NewEC256Key(t)
	kid := "key-1"

	api.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, test.NewEC256Key(t), kid, ""),
		},
	})
	api.SetWITBundles(makeWITBundle(t, witTD, key, kid))

	src, err := workloadapi.NewWITSource(t.Context(), withAddr(api))
	require.NoError(t, err)
	defer src.Close()

	svid, err := src.GetWITSVIDForID(witFooID)
	require.NoError(t, err)
	assert.Equal(t, witFooID, svid.ID)

	// Push an update replacing witFooID with witBarID.
	api.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witBarID, key, test.NewEC256Key(t), kid, ""),
		},
	})

	require.NoError(t, src.WaitUntilUpdated(t.Context()))

	_, err = src.GetWITSVIDForID(witFooID)
	require.Error(t, err)

	svid, err = src.GetWITSVIDForID(witBarID)
	require.NoError(t, err)
	assert.Equal(t, witBarID, svid.ID)
}

func TestWITSourceUpdatedChannel(t *testing.T) {
	api := fakeworkloadapi.New(t)
	t.Cleanup(api.Stop)

	src := witSourceSetup(t, api)

	key := test.NewEC256Key(t)
	kid := "key-1"
	api.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witBarID, key, test.NewEC256Key(t), kid, ""),
		},
	})

	select {
	case <-src.Updated():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Updated() notification")
	}
}

// witSourceSetup configures the fake API with one WIT-SVID and one bundle and
// returns a WITSource that has completed its initial sync. The source is
// closed automatically when the test finishes.
func witSourceSetup(t *testing.T, api *fakeworkloadapi.WorkloadAPI) *workloadapi.WITSource {
	t.Helper()
	key := test.NewEC256Key(t)
	cnfKey := test.NewEC256Key(t)
	kid := "key-1"

	api.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{
			makeWITSVIDProto(t, witFooID, key, cnfKey, kid, ""),
		},
	})
	api.SetWITBundles(makeWITBundle(t, witTD, key, kid))

	src, err := workloadapi.NewWITSource(t.Context(), withAddr(api))
	require.NoError(t, err)
	t.Cleanup(func() { src.Close() })
	return src
}
