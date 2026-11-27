package brokerapi

import (
	"context"
	"errors"
	"sync"
)

const (
	x509SVIDWatchName    = "X.509-SVIDs"
	x509BundlesWatchName = "X.509 bundles"
	jwtBundlesWatchName  = "JWT bundles"
)

// sourceBase holds the goroutine lifecycle and update-notification machinery
// shared by all sources.
type sourceBase struct {
	ctx    context.Context
	cancel func()

	wg sync.WaitGroup

	closeMtx sync.Mutex
	closed   bool

	updatedCh chan struct{}
	doneCh    chan struct{}
	doneOnce  sync.Once

	errMtx    sync.Mutex
	watchErrs map[string]error
}

func newSourceBase() sourceBase {
	ctx, cancel := context.WithCancel(context.Background())
	return sourceBase{
		ctx:       ctx,
		cancel:    cancel,
		updatedCh: make(chan struct{}, 1),
		doneCh:    make(chan struct{}),
		watchErrs: make(map[string]error),
	}
}

func (b *sourceBase) drainUpdated() {
	select {
	case <-b.updatedCh:
	default:
	}
}

func (b *sourceBase) triggerUpdated() {
	select {
	case b.updatedCh <- struct{}{}:
	default:
	}
}

func (b *sourceBase) waitUntilUpdated(ctx context.Context) error {
	select {
	case <-b.updatedCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *sourceBase) updated() <-chan struct{} {
	return b.updatedCh
}

func (b *sourceBase) done() <-chan struct{} {
	return b.doneCh
}

func (b *sourceBase) setWatchError(name string, err error) {
	if err == nil {
		return
	}

	b.errMtx.Lock()
	b.watchErrs[name] = err
	b.errMtx.Unlock()
}

func (b *sourceBase) clearWatchError(name string) {
	b.errMtx.Lock()
	delete(b.watchErrs, name)
	b.errMtx.Unlock()
}

func (b *sourceBase) lastWatchError() error {
	b.errMtx.Lock()
	defer b.errMtx.Unlock()

	switch len(b.watchErrs) {
	case 0:
		return nil
	case 1:
		for _, err := range b.watchErrs {
			return err
		}
	}

	errs := make([]error, 0, len(b.watchErrs))
	for _, err := range b.watchErrs {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (b *sourceBase) markWatchDone() {
	b.doneOnce.Do(func() {
		close(b.doneCh)
	})
}

// close cancels the background goroutines and waits for them to exit. It is
// idempotent.
func (b *sourceBase) close() error {
	b.closeMtx.Lock()
	defer b.closeMtx.Unlock()
	if !b.closed {
		b.cancel()
		b.wg.Wait()
		b.closed = true
		b.markWatchDone()
	}
	return nil
}

func joinWatchError(err, watchErr error) error {
	if watchErr == nil {
		return err
	}
	return errors.Join(err, watchErr)
}

func (b *sourceBase) checkClosed() error {
	b.closeMtx.Lock()
	defer b.closeMtx.Unlock()
	if b.closed {
		return errSourceClosed
	}
	return nil
}

var errSourceClosed = errors.New("source is closed")
