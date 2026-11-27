package brokerapi

import (
	"context"
	"errors"
	"time"

	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type recvFunc[T any] func() (T, error)
type openFunc[T any] func(context.Context) (recvFunc[T], error)

type watchTerminalError struct {
	err error
}

func (e watchTerminalError) Error() string {
	return e.err.Error()
}

func (e watchTerminalError) Unwrap() error {
	return e.err
}

func newWatchTerminalError(err error) error {
	return watchTerminalError{err: err}
}

// watch repeatedly establishes a stream and receives responses from it until
// the context is canceled or a terminal error is encountered. Transient errors
// are retried using the given backoff.
func watch[T any](
	ctx context.Context,
	log logger.Logger,
	backoffStrategy workloadapi.BackoffStrategy,
	name string,
	open openFunc[T],
	update func(T) error,
	onClear func(),
	onError func(error),
) error {
	backoff := backoffStrategy.NewBackoff()
	for {
		err := watchStream(ctx, log, backoff, name, open, update, onError)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		notifyError(onError, err)

		var terminal watchTerminalError
		if errors.As(err, &terminal) {
			log.Errorf("Canceling %s watch: %v", name, err)
			return err
		}

		code := status.Code(err)
		switch code {
		case codes.InvalidArgument, codes.Unimplemented:
			log.Errorf("Canceling %s watch: %v", name, err)
			return err
		case codes.NotFound:
			if onClear != nil {
				onClear()
			}
			log.Errorf("Canceling %s watch: %v", name, err)
			return err
		case codes.PermissionDenied:
			if onClear != nil {
				onClear()
			}
		}

		log.Errorf("Failed to watch %s: %v", name, err)
		retryAfter := backoff.Next()
		log.Debugf("Retrying %s watch in %s", name, retryAfter)
		select {
		case <-time.After(retryAfter):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func watchStream[T any](
	ctx context.Context,
	log logger.Logger,
	backoff workloadapi.Backoff,
	name string,
	open openFunc[T],
	update func(T) error,
	onError func(error),
) error {
	recv, err := open(ctx)
	if err != nil {
		return err
	}

	for {
		response, err := recv()
		if err != nil {
			return err
		}

		backoff.Reset()
		if err := update(response); err != nil {
			var terminal watchTerminalError
			if errors.As(err, &terminal) {
				return err
			}
			log.Errorf("Failed to parse %s response: %v", name, err)
			notifyError(onError, err)
		}
	}
}

func notifyError(onError func(error), err error) {
	if onError != nil {
		onError(err)
	}
}
