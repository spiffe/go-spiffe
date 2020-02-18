package tlsworkload

import (
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/spiffex509"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Option is used to provide additional options to the TLS workload.
type Option interface{}

// WithWorkloadAPIOptions provides additional options for interactions with
// the WorkloadAPI.
func WithWorkloadAPIOptions(options ...workloadapi.Option) Option {
	panic("not implemented")
}

// WithDefaultX509SVIDPicker picks an X509-SVID as the default X509-SVID. By
// default, the first X509-SVID returned by the Workload API is used.
func WithDefaultX509SVIDPicker(picker func([]*spiffex509.SVID) (*spiffex509.SVID, error)) Option {
	panic("not implemented")
}

// WithOnUpdate provides a callback to be invoked when the workload is updated.
func WithOnUpdate(onUpdate func()) Option {
	panic("not implemented")
}

// WithOnError provides a callback to be invoked when the workload encounters
// an error communicating with the Workload API.
func WithOnError(onError func(error)) Option {
	panic("not implemented")
}

// WithLogger provides a logger to the workload.
func WithLogger(logger logger.Logger) Option {
	panic("not implemented")
}

// WithNoWait causes Open() to return before the workload has received the
// initial update.
func WithNoWait() Option {
	panic("not implemented")
}
