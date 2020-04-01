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

type fakewatcher struct {
	t              *testing.T
	nextRefresh    time.Duration
	expectedBundle *spiffebundle.Bundle
	expectedErr    string
	cancel         context.CancelFunc
}

func (w *fakewatcher) NextRefresh(refreshHint time.Duration) time.Duration {
	return w.nextRefresh
}

func (w *fakewatcher) OnUpdate(bundle *spiffebundle.Bundle) {
	assert.True(w.t, bundle.Equal(w.expectedBundle))
	w.cancel()
}

func (w *fakewatcher) OnError(err error) {
	assert.EqualError(w.t, err, w.expectedErr)
	w.cancel()
}

func TestWatchBundle_OnUpate(t *testing.T) {
	bundle1 := &spiffebundle.Bundle{}
	fetchBundleCallback = func(ctx context.Context, trustDomain spiffeid.TrustDomain, url string, option ...FetchOption) (*spiffebundle.Bundle, error) {
		return bundle1, nil
	}

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ctx, cancel := context.WithCancel(context.Background())
	watcher := &fakewatcher{
		t:              t,
		nextRefresh:    1 * time.Second,
		expectedBundle: bundle1,
		cancel:         cancel,
	}

	err := WatchBundle(ctx, td, "some url", watcher)
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
		t:           t,
		nextRefresh: 1 * time.Second,
		expectedErr: fetchErr.Error(),
		cancel:      cancel,
	}

	err := WatchBundle(ctx, td, "some url", watcher)
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
