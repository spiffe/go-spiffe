package jwtworkload

import (
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type Option interface{}

func WithWorkloadAPIOptions(options ...workloadapi.Option) Option {
	panic("not implemented")
}

// WithOnUpdate provides a callback to be invoked when the workload is updated
func WithOnUpdate(onUpdate func()) Option {
	panic("not implemented")
}

// WithOnError provides a callback to be invoked when the workload encounters
// an error communicating with the Workload API.
func WithOnError(onError func(error)) Option {
	panic("not implemented")
}

// WithLogger provides a logger to the workload
func WithLogger(logger logger.Logger) Option {
	panic("not implemented")
}

// WithNoWait causes Open() to return before the workload has received the
// initial update.
func WithNoWait() Option {
	panic("not implemented")
}
