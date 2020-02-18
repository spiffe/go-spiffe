package bundleendpoint

import (
	"context"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffebundle"
)

// Watcher is an interface used to watch for bundle updates.
type Watcher interface {
	// NextRefresh is called by Watch to determine when the next refresh
	// should take place. A refresh hint is provided, which can be zero, meaning
	// the watcher is free to choose its own refresh cadence. If the refresh hint
	// is non-zero, the watcher SHOULD return a next refresh time at or below
	// that to ensure the bundle stays up-to-date.
	NextRefresh(refreshHint time.Duration) time.Duration

	// OnUpdate is called when a bundle has been updated. If a bundle is
	// fetched but has not changed from the previously fetched bundle, OnUpdate
	// will not be called.
	OnUpdate(*spiffebundle.Bundle)

	// OnError is called if there is an error fetching the bundle from the
	// endpoint.
	OnError(err error)
}

// WatchBundle watches a bundle on a bundle endpoint. It returns when the
// context is canceled, returning ctx.Err().
func WatchBundle(ctx context.Context, url string, watcher Watcher, options ...FetchOption) error {
	panic("not implemented")
}
