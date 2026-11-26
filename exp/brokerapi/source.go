package brokerapi

import (
	"context"
	"errors"
	"sync"
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

	watchMtx   sync.Mutex
	watchCount int
	errMtx     sync.Mutex
	watchErr   error
}

func newSourceBase(watchCount int) sourceBase {
	ctx, cancel := context.WithCancel(context.Background())
	return sourceBase{
		ctx:        ctx,
		cancel:     cancel,
		updatedCh:  make(chan struct{}, 1),
		doneCh:     make(chan struct{}),
		watchCount: watchCount,
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

func (b *sourceBase) recordWatchError(err error) {
	if err == nil {
		return
	}

	b.errMtx.Lock()
	b.watchErr = err
	b.errMtx.Unlock()
}

func (b *sourceBase) lastWatchError() error {
	b.errMtx.Lock()
	defer b.errMtx.Unlock()
	return b.watchErr
}

func (b *sourceBase) markWatchDone() {
	b.watchMtx.Lock()
	if b.watchCount > 0 {
		b.watchCount--
	}
	done := b.watchCount == 0
	b.watchMtx.Unlock()

	if done {
		b.doneOnce.Do(func() {
			close(b.doneCh)
		})
	}
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
