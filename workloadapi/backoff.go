package workloadapi

import (
	"time"

	"github.com/spiffe/go-spiffe/v2/internal/backoff"
)

// BackoffStrategy provides backoff facilities.
type BackoffStrategy interface {
	// NewBackoff returns a new backoff for the strategy. The returned
	// Backoff is in the same state that it would be in after a call to
	// Reset().
	NewBackoff() Backoff
}

// Backoff provides backoff for a workload API operation.
type Backoff interface {
	// Next returns the next backoff period.
	Next() time.Duration

	// Reset() resets the backoff.
	Reset()
}

type defaultBackoffStrategy struct{}

func (defaultBackoffStrategy) NewBackoff() Backoff {
	return backoff.NewLinear()
}
