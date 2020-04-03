package federation

import (
	"context"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// fetchBundleCallback enables us to test this module without having the actual FetchBundle
// implementation.
// TODO: Once support for setting up a fake federation server is added, we should get
// rid of this.
var fetchBundleCallback = FetchBundle

// BundleWatcher is used by WatchBundle to provide the caller with bundle updates and
// control the next refresh time.
type BundleWatcher interface {
	// NextRefresh is called by WatchBundle to determine when the next refresh
	// should take place. A refresh hint is provided, which can be zero, meaning
	// the watcher is free to choose its own refresh cadence. If the refresh hint
	// is greater than zero, the watcher SHOULD return a next refresh time at or
	// below that to ensure the bundle stays up-to-date.
	NextRefresh(refreshHint time.Duration) time.Duration

	// OnUpdate is called when a bundle has been updated. If a bundle is
	// fetched but has not changed from the previously fetched bundle, OnUpdate
	// will not be called. This function is called synchronously by WatchBundle
	// and therefore should have a short execution time to prevent blocking the
	// watch.
	OnUpdate(*spiffebundle.Bundle)

	// OnError is called if there is an error fetching the bundle from the
	// endpoint. This function is called synchronously by WatchBundle
	// and therefore should have a short execution time to prevent blocking the
	// watch.
	OnError(err error)
}

// WatchBundle watches a bundle on a bundle endpoint. It returns when the
// context is canceled, returning ctx.Err().
func WatchBundle(ctx context.Context, trustDomain spiffeid.TrustDomain, url string, watcher BundleWatcher, options ...FetchOption) error {
	if watcher == nil {
		return federationErr.New("watcher cannot be nil")
	}

	latestBundle := &spiffebundle.Bundle{}
	var timer *time.Timer
	for {
		bundle, err := fetchBundleCallback(ctx, trustDomain, url, options)
		switch {
		// Context was canceled when fetching bundle, so to avoid
		// more calls to FetchBundle (because the timer could be expired at
		// this point) we return now.
		case ctx.Err() == context.Canceled:
			return ctx.Err()
		case err != nil:
			watcher.OnError(err)
		case !latestBundle.Equal(bundle):
			watcher.OnUpdate(bundle)
			latestBundle = bundle
		}

		var nextRefresh time.Duration
		if refreshHint, ok := latestBundle.RefreshHint(); ok {
			nextRefresh = watcher.NextRefresh(refreshHint)
		} else {
			nextRefresh = watcher.NextRefresh(0)
		}

		if timer == nil {
			timer = time.NewTimer(nextRefresh)
			defer timer.Stop()
		} else {
			timer.Reset(nextRefresh)
		}

		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
