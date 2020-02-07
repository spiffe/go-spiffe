package grpcworkload

import "github.com/spiffe/go-spiffe/v2/workloadapi"

// Options are used to influence optional behavior. An Option is also a
// DialOption.
type Option interface{}

func WithWorkloadAPIOptions(options ...workloadapi.Option) Option {
	panic("not implemented")
}
