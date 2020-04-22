package federation_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebundleendpoint"
	"github.com/stretchr/testify/assert"
)

func TestWatchBundle_OnUpate(t *testing.T) {
	var watcher *fakewatcher
	ca1 := test.NewCA(t)
	bundle1 := spiffebundle.FromX509Bundle(ca1.Bundle(td))
	bundle1.SetRefreshHint(time.Second)
	ca2 := test.NewCA(t)
	bundle2 := spiffebundle.FromX509Bundle(ca2.Bundle(td))
	bundle2.SetRefreshHint(2 * time.Second)
	bundles := []*spiffebundle.Bundle{bundle1, bundle2}

	be := fakebundleendpoint.New(t, fakebundleendpoint.WithTestBundles(bundle1, bundle2))
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	watcher = &fakewatcher{
		t:               t,
		nextRefresh:     time.Second,
		expectedBundles: bundles,
		cancel: func() {
			if watcher.onUpdateCalls > 1 {
				cancel()
			}
		},
		latestBundle: &spiffebundle.Bundle{},
	}

	err := federation.WatchBundle(ctx, td, be.FetchBundleURL(), watcher, federation.WithWebPKIRoots(be.RootCAs()))
	assert.Equal(t, 2, watcher.onUpdateCalls)
	assert.Equal(t, 0, watcher.onErrorCalls)
	assert.Equal(t, context.Canceled, err)
}

func TestWatchBundle_OnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	watcher := &fakewatcher{
		t:            t,
		nextRefresh:  time.Second,
		expectedErr:  `federation: could not GET bundle: Get "?wrong%20url"?: unsupported protocol scheme ""`,
		cancel:       cancel,
		latestBundle: &spiffebundle.Bundle{},
	}

	err := federation.WatchBundle(ctx, td, "wrong url", watcher)
	assert.Equal(t, 0, watcher.onUpdateCalls)
	assert.Equal(t, 1, watcher.onErrorCalls)
	assert.Equal(t, context.Canceled, err)
}

func TestWatchBundle_NilWatcher(t *testing.T) {
	err := federation.WatchBundle(context.Background(), td, "some url", nil)
	assert.EqualError(t, err, "federation: watcher cannot be nil")
}

func TestWatchBundle_FetchBundleCanceled(t *testing.T) {
	be := fakebundleendpoint.New(t)
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	watcher := &fakewatcher{
		t:           t,
		nextRefresh: time.Second,
	}
	cancel()
	err := federation.WatchBundle(ctx, td, be.FetchBundleURL(), watcher, federation.WithWebPKIRoots(be.RootCAs()))
	assert.Equal(t, context.Canceled, err)
}

type fakewatcher struct {
	t               *testing.T
	nextRefresh     time.Duration
	expectedBundles []*spiffebundle.Bundle
	expectedErr     string
	cancel          context.CancelFunc
	onUpdateCalls   int
	onErrorCalls    int
	latestBundle    *spiffebundle.Bundle
}

func (w *fakewatcher) NextRefresh(refreshHint time.Duration) time.Duration {
	if rh, ok := w.latestBundle.RefreshHint(); ok {
		assert.Equal(w.t, rh, refreshHint)
	} else {
		assert.Equal(w.t, time.Duration(0), refreshHint)
	}
	return w.nextRefresh
}

func (w *fakewatcher) OnUpdate(bundle *spiffebundle.Bundle) {
	w.latestBundle = bundle
	assert.True(w.t, bundle.Equal(w.expectedBundles[w.onUpdateCalls]))
	w.onUpdateCalls++
	w.cancel()
}

func (w *fakewatcher) OnError(err error) {
	assert.Regexp(w.t, w.expectedErr, err.Error())
	w.onErrorCalls++
	w.cancel()
}
