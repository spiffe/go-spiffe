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
}

func newSourceBase() sourceBase {
	ctx, cancel := context.WithCancel(context.Background())
	return sourceBase{
		ctx:       ctx,
		cancel:    cancel,
		updatedCh: make(chan struct{}, 1),
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

// close cancels the background goroutines and waits for them to exit. It is
// idempotent.
func (b *sourceBase) close() error {
	b.closeMtx.Lock()
	defer b.closeMtx.Unlock()
	if !b.closed {
		b.cancel()
		b.wg.Wait()
		b.closed = true
	}
	return nil
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
