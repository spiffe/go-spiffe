package federation

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/zeebo/errs"
)

func TestWatchBundle_OnUpate(t *testing.T) {
	var watcher *fakewatcher
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	bundle1 := spiffebundle.New(td)
	bundle1.SetSequenceNumber(1)
	bundle1.SetRefreshHint(500 * time.Millisecond)
	bundle2 := spiffebundle.New(td)
	bundle2.SetSequenceNumber(2)
	bundle2.SetRefreshHint(200 * time.Millisecond)
	bundles := []*spiffebundle.Bundle{bundle1, bundle2}
	fetchBundleCallback = func(ctx context.Context, trustDomain spiffeid.TrustDomain, url string, option ...FetchOption) (*spiffebundle.Bundle, error) {
		assert.Greater(t, len(bundles), 0)
		b := bundles[0]
		bundles = bundles[1:]
		return b, nil
	}
	ctx, cancel := context.WithCancel(context.Background())

	watcher = &fakewatcher{
		t:               t,
		nextRefresh:     1 * time.Second,
		expectedBundles: bundles[0:],
		cancel: func() {
			if watcher.onUpdateCalls > 1 {
				cancel()
			}
		},
		latestBundle: &spiffebundle.Bundle{},
	}

	err := WatchBundle(ctx, td, "some url", watcher)
	assert.Equal(t, 2, watcher.onUpdateCalls)
	assert.Equal(t, 0, watcher.onErrorCalls)
	assert.Equal(t, context.Canceled, err)
}

func TestWatchBundle_OnError(t *testing.T) {
	fetchErr := errs.New("oops...I did it again...")
	fetchBundleCallback = func(ctx context.Context, trustDomain spiffeid.TrustDomain, url string, option ...FetchOption) (*spiffebundle.Bundle, error) {
		return nil, fetchErr
	}

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ctx, cancel := context.WithCancel(context.Background())
	watcher := &fakewatcher{
		t:            t,
		nextRefresh:  1 * time.Second,
		expectedErr:  fetchErr.Error(),
		cancel:       cancel,
		latestBundle: &spiffebundle.Bundle{},
	}

	err := WatchBundle(ctx, td, "some url", watcher)
	assert.Equal(t, 0, watcher.onUpdateCalls)
	assert.Equal(t, 1, watcher.onErrorCalls)
	assert.Equal(t, context.Canceled, err)
}

func TestWatchBundle_NilWatcher(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	err := WatchBundle(context.Background(), td, "some url", nil)
	assert.EqualError(t, err, "federation: watcher cannot be nil")
}

func TestWatchBundle_FetchBundleCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fetchBundleCallback = func(ctx context.Context, trustDomain spiffeid.TrustDomain, url string, option ...FetchOption) (*spiffebundle.Bundle, error) {
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	watcher := &fakewatcher{
		t:           t,
		nextRefresh: 1 * time.Second,
	}

	err := WatchBundle(ctx, td, "some url", watcher)
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
	assert.EqualError(w.t, err, w.expectedErr)
	w.onErrorCalls++
	w.cancel()
}
