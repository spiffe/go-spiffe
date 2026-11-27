package brokerapi

import (
	"github.com/spiffe/go-spiffe/v2/internal/backoff"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type defaultBackoffStrategy struct{}

func (defaultBackoffStrategy) NewBackoff() workloadapi.Backoff {
	return backoff.NewLinear()
}
