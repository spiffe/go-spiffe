// Package workload has been deprecated, use the workloadapi package instead
package workload

import (
	"github.com/spiffe/go-spiffe/spiffe/workloadapi"
)

// Aliases for the workloadapi package

var (
	Dial     = workloadapi.Dial
	WithAddr = workloadapi.WithAddr
)

type (
	DialOption = workloadapi.DialOption
	Dialer     = workloadapi.Dialer
)
